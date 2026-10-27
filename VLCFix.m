// VLCFix.m
// Dylib sửa lỗi VLC iOS 4.0 (VLCKit 4.0.0-dev) đứng hình khi phát luồng http(s)/WebDAV/Google Drive.
//
// Cách làm:
//  1. Hook -[VLCMedia initWithURL:]. Nếu URL là http/https/webdav(s) trỏ tới file media (hoặc Drive alt=media),
//     đổi URL thành http://127.0.0.1:<port>/o<id>/<path gốc>.
//  2. Proxy loopback trong tiến trình nhận request của libvlc, gọi lên server thật bằng NSURLSession
//     (stack mạng của Apple, giống nPlayer/Infuse) rồi stream lại (hỗ trợ Range) -> bỏ qua TLS/HTTP riêng của libvlc.
//  3. Bắt option http-token / http-user / http-pwd mà app đặt trên VLCMedia để gắn Authorization khi gọi lên server.
//  4. Ghi log vào Documents/VLCFix.log và Documents/VLCFix-libvlc.log (xem được qua app Tệp vì VLC bật file sharing).

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>
#import <poll.h>
#import <unistd.h>
#import <errno.h>

#pragma mark - Logging

static dispatch_queue_t gLogQueue;
static NSFileHandle *gLogHandle;
static NSString *gDocsDir;

static void VFLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void VFLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[VLCFix] %@", msg);
    if (!gLogQueue) return;
    dispatch_async(gLogQueue, ^{
        if (!gLogHandle) return;
        static NSDateFormatter *df;
        if (!df) {
            df = [[NSDateFormatter alloc] init];
            df.dateFormat = @"yyyy-MM-dd HH:mm:ss.SSS";
        }
        NSString *line = [NSString stringWithFormat:@"%@ %@\n", [df stringFromDate:[NSDate date]], msg];
        NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding];
        if (d) {
            @try { [gLogHandle writeData:d]; } @catch (__unused NSException *e) {}
        }
    });
}

static NSString *VFDocPath(NSString *name) {
    return gDocsDir ? [gDocsDir stringByAppendingPathComponent:name] : nil;
}

static BOOL VFFlagExists(NSString *name) {
    NSString *p = VFDocPath(name);
    return p && [[NSFileManager defaultManager] fileExistsAtPath:p];
}

static NSFileHandle *VFOpenLogFile(NSString *name, unsigned long long maxBytes) {
    NSString *p = VFDocPath(name);
    if (!p) return nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attr = [fm attributesOfItemAtPath:p error:nil];
    if (!attr || [attr fileSize] > maxBytes) {
        [fm removeItemAtPath:p error:nil];
        [fm createFileAtPath:p contents:nil attributes:nil];
    }
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (h) [h seekToEndOfFile];
    return h;
}

static void VFSetupLogging(void) {
    gDocsDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    gLogQueue = dispatch_queue_create("vlcfix.log", DISPATCH_QUEUE_SERIAL);
    gLogHandle = VFOpenLogFile(@"VLCFix.log", 2 * 1024 * 1024);
}

// Che giá trị nhạy cảm khi ghi log.
static NSString *VFRedact(NSString *key, id val) {
    NSString *k = key.lowercaseString;
    if ([k containsString:@"token"] || [k containsString:@"pwd"] || [k containsString:@"pass"] ||
        [k containsString:@"auth"] || [k containsString:@"cookie"] || [k containsString:@"user"]) {
        return @"<redacted>";
    }
    return [NSString stringWithFormat:@"%@", val];
}

// URL dùng để ghi log: bỏ userinfo, che query.
static NSString *VFSafeURL(NSURL *u) {
    if (!u) return @"(nil)";
    NSURLComponents *c = [NSURLComponents componentsWithURL:u resolvingAgainstBaseURL:NO];
    if (!c) return @"(invalid)";
    c.user = nil;
    c.password = nil;
    if (c.percentEncodedQuery.length) c.percentEncodedQuery = @"...";
    c.fragment = nil;
    return c.string ?: @"(invalid)";
}

#pragma mark - Origin registry

@interface VFOrigin : NSObject
@property (nonatomic) int oid;
@property (nonatomic, copy) NSString *scheme;   // http | https
@property (nonatomic, copy) NSString *host;
@property (nonatomic) int port;                 // 0 = mặc định
@property (nonatomic, copy) NSString *user;
@property (nonatomic, copy) NSString *pass;
@property (nonatomic, copy) NSString *bearer;
@end
@implementation VFOrigin
@end

static NSMutableDictionary<NSString *, VFOrigin *> *gOriginsByKey;
static NSMutableDictionary<NSNumber *, VFOrigin *> *gOriginsById;
static int gNextOriginId = 1;
static NSObject *gRegistryLock;
static const void *kOriginKey = &kOriginKey;

static uint16_t gProxyPort = 0;
static int gListenFd = -1;
static dispatch_queue_t gHandlerQueue;

#pragma mark - Socket helpers

static BOOL VFSendAll(int fd, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    while (n > 0) {
        ssize_t w = send(fd, b, n, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return NO;
        }
        if (w == 0) return NO;
        b += w;
        n -= (size_t)w;
    }
    return YES;
}

static BOOL VFSendString(int fd, NSString *s) {
    NSData *d = [s dataUsingEncoding:NSISOLatin1StringEncoding allowLossyConversion:YES];
    return VFSendAll(fd, d.bytes, d.length);
}

static BOOL VFClientClosed(int fd) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int r = poll(&pfd, 1, 0);
    if (r <= 0) return NO;
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) return YES;
    if (pfd.revents & POLLIN) {
        char c;
        ssize_t n = recv(fd, &c, 1, MSG_PEEK | MSG_DONTWAIT);
        if (n == 0) return YES;
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return YES;
    }
    return NO;
}

static NSString *VFReason(NSInteger code) {
    switch (code) {
        case 200: return @"OK";
        case 204: return @"No Content";
        case 206: return @"Partial Content";
        case 301: return @"Moved Permanently";
        case 302: return @"Found";
        case 304: return @"Not Modified";
        case 400: return @"Bad Request";
        case 401: return @"Unauthorized";
        case 403: return @"Forbidden";
        case 404: return @"Not Found";
        case 405: return @"Method Not Allowed";
        case 416: return @"Range Not Satisfiable";
        case 429: return @"Too Many Requests";
        case 500: return @"Internal Server Error";
        case 502: return @"Bad Gateway";
        case 503: return @"Service Unavailable";
        default: return @"Status";
    }
}

static void VFSendSimple(int fd, NSInteger code, NSString *body) {
    NSString *s = [NSString stringWithFormat:
                   @"HTTP/1.1 %ld %@\r\nContent-Type: text/plain\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n%@",
                   (long)code, VFReason(code), (unsigned long)body.length, body];
    VFSendString(fd, s);
}

#pragma mark - Relay (một request client <-> NSURLSession)

@interface VFRelay : NSObject <NSURLSessionDataDelegate>
@property (nonatomic) int fd;
@property (nonatomic) BOOL isHead;
@property (nonatomic) BOOL headerSent;
@property (nonatomic) BOOL clientGone;
@property (nonatomic) BOOL allowInsecure;
@property (nonatomic) unsigned long long sent;
@property (nonatomic) NSInteger status;
@property (nonatomic, copy) NSString *originHost;
@property (nonatomic, copy) NSString *user;
@property (nonatomic, copy) NSString *pass;
@property (nonatomic, copy) NSString *tag;
@property (nonatomic, strong) dispatch_semaphore_t done;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSURLSessionDataTask *task;
@end

@implementation VFRelay

- (instancetype)init {
    if ((self = [super init])) {
        _done = dispatch_semaphore_create(0);
    }
    return self;
}

- (NSString *)headerValue:(NSDictionary *)all name:(NSString *)name {
    for (id k in all) {
        if ([k isKindOfClass:[NSString class]] && [(NSString *)k caseInsensitiveCompare:name] == NSOrderedSame) {
            return [NSString stringWithFormat:@"%@", all[k]];
        }
    }
    return nil;
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    NSString *m = challenge.protectionSpace.authenticationMethod;
    if ([m isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        if (self.allowInsecure && challenge.protectionSpace.serverTrust) {
            completionHandler(NSURLSessionAuthChallengeUseCredential,
                              [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
        } else {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        }
        return;
    }
    BOOL httpAuth = [m isEqualToString:NSURLAuthenticationMethodHTTPBasic] ||
                    [m isEqualToString:NSURLAuthenticationMethodHTTPDigest] ||
                    [m isEqualToString:NSURLAuthenticationMethodNTLM];
    BOOL sameHost = [challenge.protectionSpace.host caseInsensitiveCompare:self.originHost ?: @""] == NSOrderedSame;
    if (httpAuth && sameHost && self.user.length && challenge.previousFailureCount == 0) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialWithUser:self.user
                                                     password:self.pass ?: @""
                                                  persistence:NSURLCredentialPersistenceNone]);
        return;
    }
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    if ([response isKindOfClass:[NSHTTPURLResponse class]] && !self.clientGone) {
        NSHTTPURLResponse *h = (NSHTTPURLResponse *)response;
        NSDictionary *all = h.allHeaderFields;
        self.status = h.statusCode;
        NSMutableString *out = [NSMutableString stringWithFormat:@"HTTP/1.1 %ld %@\r\n", (long)h.statusCode, VFReason(h.statusCode)];
        NSArray *names = @[@"Content-Type", @"Content-Length", @"Content-Range", @"Accept-Ranges",
                           @"ETag", @"Last-Modified"];
        for (NSString *n in names) {
            NSString *v = [self headerValue:all name:n];
            if (v.length) [out appendFormat:@"%@: %@\r\n", n, v];
        }
        [out appendString:@"Connection: close\r\n\r\n"];
        if (!VFSendString(self.fd, out)) {
            self.clientGone = YES;
            [dataTask cancel];
        } else {
            self.headerSent = YES;
        }
        VFLog(@"%@ upstream -> %ld len=%@ range=%@", self.tag, (long)h.statusCode,
              [self headerValue:all name:@"Content-Length"] ?: @"?",
              [self headerValue:all name:@"Content-Range"] ?: @"-");
    }
    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    if (self.clientGone || self.isHead) return;
    __block BOOL ok = YES;
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange range, BOOL *stop) {
        if (!VFSendAll(self.fd, bytes, range.length)) {
            ok = NO;
            *stop = YES;
        }
    }];
    if (ok) {
        self.sent += data.length;
    } else {
        self.clientGone = YES;
        [dataTask cancel];
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    if (error && error.code != NSURLErrorCancelled) {
        VFLog(@"%@ upstream error: %@ (%ld) %@", self.tag, error.domain, (long)error.code, error.localizedDescription);
        if (!self.headerSent && !self.clientGone) {
            VFSendSimple(self.fd, 502, [NSString stringWithFormat:@"VLCFix upstream error: %@", error.localizedDescription]);
            self.headerSent = YES;
        }
    }
    VFLog(@"%@ done, sent=%llu bytes%@", self.tag, self.sent, self.clientGone ? @" (client closed)" : @"");
    dispatch_semaphore_signal(self.done);
}

@end

#pragma mark - Proxy server

static NSString *VFBasicHeader(NSString *user, NSString *pass) {
    NSString *up = [NSString stringWithFormat:@"%@:%@", user ?: @"", pass ?: @""];
    return [@"Basic " stringByAppendingString:[[up dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0]];
}

static void VFHandleClient(int fd) {
    @autoreleasepool {
        // ---- đọc request ----
        NSMutableData *buf = [NSMutableData data];
        NSData *term = [@"\r\n\r\n" dataUsingEncoding:NSASCIIStringEncoding];
        BOOL gotHeaders = NO;
        while (buf.length < 32 * 1024) {
            uint8_t tmp[4096];
            ssize_t n = recv(fd, tmp, sizeof tmp, 0);
            if (n <= 0) break;
            [buf appendBytes:tmp length:(NSUInteger)n];
            if ([buf rangeOfData:term options:0 range:NSMakeRange(0, buf.length)].location != NSNotFound) {
                gotHeaders = YES;
                break;
            }
        }
        if (!gotHeaders) {
            close(fd);
            return;
        }
        NSString *req = [[NSString alloc] initWithData:buf encoding:NSISOLatin1StringEncoding];
        NSArray<NSString *> *lines = [req componentsSeparatedByString:@"\r\n"];
        NSArray<NSString *> *parts = [lines.firstObject componentsSeparatedByString:@" "];
        if (parts.count < 2) {
            VFSendSimple(fd, 400, @"bad request");
            close(fd);
            return;
        }
        NSString *method = parts[0].uppercaseString;
        NSString *target = parts[1];
        NSMutableDictionary<NSString *, NSString *> *hdr = [NSMutableDictionary dictionary];
        for (NSUInteger i = 1; i < lines.count; i++) {
            NSString *ln = lines[i];
            NSRange r = [ln rangeOfString:@":"];
            if (r.location == NSNotFound || r.location == 0) continue;
            NSString *k = [[ln substringToIndex:r.location] lowercaseString];
            NSString *v = [[ln substringFromIndex:r.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            hdr[k] = v;
        }
        BOOL isHead = [method isEqualToString:@"HEAD"];
        if (!isHead && ![method isEqualToString:@"GET"]) {
            VFSendSimple(fd, 405, @"only GET/HEAD");
            close(fd);
            return;
        }
        // ---- tìm origin: /o<id><rest> ----
        if (![target hasPrefix:@"/o"]) {
            VFSendSimple(fd, 404, @"not found");
            close(fd);
            return;
        }
        NSScanner *sc = [NSScanner scannerWithString:target];
        sc.scanLocation = 2;
        int oid = 0;
        if (![sc scanInt:&oid]) {
            VFSendSimple(fd, 404, @"not found");
            close(fd);
            return;
        }
        NSString *rest = [target substringFromIndex:sc.scanLocation];
        if (rest.length == 0) rest = @"/";
        if (![rest hasPrefix:@"/"] && ![rest hasPrefix:@"?"]) rest = [@"/" stringByAppendingString:rest];

        NSString *scheme, *host, *user, *pass, *bearer;
        int port;
        @synchronized (gRegistryLock) {
            VFOrigin *o = gOriginsById[@(oid)];
            scheme = o.scheme;
            host = o.host;
            port = o.port;
            user = o.user;
            pass = o.pass;
            bearer = o.bearer;
        }
        if (!host) {
            VFSendSimple(fd, 404, @"unknown origin");
            close(fd);
            return;
        }
        NSString *hostPart = [host containsString:@":"] ? [NSString stringWithFormat:@"[%@]", host] : host;
        NSString *portPart = port > 0 ? [NSString stringWithFormat:@":%d", port] : @"";
        NSURL *upstream = [NSURL URLWithString:[NSString stringWithFormat:@"%@://%@%@%@", scheme, hostPart, portPart, rest]];
        if (!upstream) {
            VFSendSimple(fd, 400, @"bad upstream url");
            close(fd);
            return;
        }

        NSMutableURLRequest *ur = [NSMutableURLRequest requestWithURL:upstream
                                                          cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                      timeoutInterval:30];
        ur.HTTPMethod = isHead ? @"HEAD" : @"GET";
        for (NSString *k in @[@"range", @"if-range", @"accept", @"referer", @"cookie"]) {
            if (hdr[k].length) [ur setValue:hdr[k] forHTTPHeaderField:k];
        }
        [ur setValue:(hdr[@"user-agent"].length ? hdr[@"user-agent"] : @"VLC/4.0.0 LibVLC/4.0.0") forHTTPHeaderField:@"User-Agent"];
        [ur setValue:@"identity" forHTTPHeaderField:@"Accept-Encoding"];
        if (bearer.length) {
            [ur setValue:[@"Bearer " stringByAppendingString:bearer] forHTTPHeaderField:@"Authorization"];
        } else if (hdr[@"authorization"].length) {
            [ur setValue:hdr[@"authorization"] forHTTPHeaderField:@"Authorization"];
        } else if (user.length) {
            [ur setValue:VFBasicHeader(user, pass) forHTTPHeaderField:@"Authorization"];
        }

        static int seq = 0;
        int mySeq;
        @synchronized (gRegistryLock) { mySeq = ++seq; }

        VFRelay *relay = [[VFRelay alloc] init];
        relay.fd = fd;
        relay.isHead = isHead;
        relay.originHost = host;
        relay.user = user;
        relay.pass = pass;
        BOOL google = [host.lowercaseString hasSuffix:@"google.com"] || [host.lowercaseString hasSuffix:@"googleapis.com"] ||
                      [host.lowercaseString hasSuffix:@"googleusercontent.com"];
        relay.allowInsecure = !google && !VFFlagExists(@"VLCFix.strict");
        relay.tag = [NSString stringWithFormat:@"[#%d %@ %@]", mySeq, method, host];

        VFLog(@"%@ %@ %@ range=%@ auth=%@", relay.tag, method, VFSafeURL(upstream), hdr[@"range"] ?: @"-",
              bearer.length ? @"bearer" : (user.length ? @"basic" : (hdr[@"authorization"].length ? @"client" : @"none")));

        NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cfg.timeoutIntervalForRequest = 30;
        cfg.timeoutIntervalForResource = 24 * 3600;
        cfg.URLCache = nil;
        cfg.requestCachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
        NSOperationQueue *q = [[NSOperationQueue alloc] init];
        q.maxConcurrentOperationCount = 1;
        relay.session = [NSURLSession sessionWithConfiguration:cfg delegate:relay delegateQueue:q];
        relay.task = [relay.session dataTaskWithRequest:ur];
        [relay.task resume];

        while (dispatch_semaphore_wait(relay.done, dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC)) != 0) {
            if (!relay.clientGone && VFClientClosed(fd)) {
                relay.clientGone = YES;
                [relay.task cancel];
            }
        }
        [relay.session invalidateAndCancel];
        close(fd);
    }
}

static int VFMakeListener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_len = sizeof a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 32) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void VFAcceptLoop(void) {
    int lfd = gListenFd;
    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            VFLog(@"accept failed errno=%d, relistening on %u", errno, gProxyPort);
            close(lfd);
            for (;;) {
                lfd = VFMakeListener(gProxyPort);
                if (lfd >= 0) break;
                sleep(1);
            }
            gListenFd = lfd;
            continue;
        }
        int one = 1;
        setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        struct timeval rt = {20, 0};   // chờ header request
        struct timeval st = {600, 0};  // gửi: cho phép VLC tạm dừng lâu
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof rt);
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &st, sizeof st);
        dispatch_async(gHandlerQueue, ^{ VFHandleClient(cfd); });
    }
}

static BOOL VFEnsureProxy(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gHandlerQueue = dispatch_queue_create("vlcfix.handlers", DISPATCH_QUEUE_CONCURRENT);
        int fd = VFMakeListener(0);
        if (fd < 0) {
            VFLog(@"cannot create proxy listener, errno=%d", errno);
            return;
        }
        struct sockaddr_in a;
        socklen_t len = sizeof a;
        if (getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
            close(fd);
            return;
        }
        gListenFd = fd;
        gProxyPort = ntohs(a.sin_port);
        VFLog(@"proxy listening on 127.0.0.1:%u", gProxyPort);
        [NSThread detachNewThreadWithBlock:^{
            [[NSThread currentThread] setName:@"vlcfix.accept"];
            VFAcceptLoop();
        }];
    });
    return gProxyPort != 0;
}

#pragma mark - URL rewriting

static BOOL VFIsMediaPath(NSString *path) {
    static NSSet *exts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        exts = [NSSet setWithArray:@[
            @"mkv", @"mp4", @"m4v", @"mov", @"avi", @"ts", @"m2ts", @"mts", @"wmv", @"flv", @"webm", @"mpg", @"mpeg",
            @"mpe", @"vob", @"3gp", @"3g2", @"ogv", @"ogm", @"divx", @"rmvb", @"rm", @"asf", @"mxf", @"f4v", @"iso",
            @"mp3", @"m4a", @"aac", @"flac", @"ogg", @"oga", @"opus", @"wav", @"wma", @"ape", @"alac", @"aiff", @"mka"
        ]];
    });
    return [exts containsObject:path.pathExtension.lowercaseString];
}

static NSURL *VFProxify(NSURL *url, VFOrigin **outOrigin) {
    if (!url) return nil;
    NSString *scheme = url.scheme.lowercaseString;
    BOOL secure = [scheme isEqualToString:@"https"] || [scheme isEqualToString:@"webdavs"];
    BOOL plain = [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"webdav"];
    if (!secure && !plain) return nil;
    if (VFFlagExists(@"VLCFix.off")) return nil;

    NSURLComponents *c = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSString *host = c.host;
    if (!host.length) return nil;
    NSString *lh = host.lowercaseString;
    if ([lh isEqualToString:@"localhost"] || [lh isEqualToString:@"127.0.0.1"] || [lh isEqualToString:@"::1"]) return nil;

    NSString *query = c.percentEncodedQuery ?: @"";
    BOOL driveMedia = [lh hasSuffix:@"googleapis.com"] && [query containsString:@"alt=media"];
    if (!(driveMedia || VFFlagExists(@"VLCFix.all") || VFIsMediaPath(c.path ?: @""))) return nil;
    if (!VFEnsureProxy()) return nil;

    NSString *realScheme = secure ? @"https" : @"http";
    int port = c.port ? c.port.intValue : 0;
    NSString *key = [NSString stringWithFormat:@"%@://%@:%d", realScheme, lh, port];
    VFOrigin *o;
    @synchronized (gRegistryLock) {
        o = gOriginsByKey[key];
        if (!o) {
            o = [[VFOrigin alloc] init];
            o.oid = gNextOriginId++;
            o.scheme = realScheme;
            o.host = host;
            o.port = port;
            gOriginsByKey[key] = o;
            gOriginsById[@(o.oid)] = o;
        }
        if (c.user.length) {
            o.user = c.user;
            o.pass = c.password;
        }
    }
    NSString *path = c.percentEncodedPath.length ? c.percentEncodedPath : @"/";
    if (![path hasPrefix:@"/"]) path = [@"/" stringByAppendingString:path];
    NSString *s = [NSString stringWithFormat:@"http://127.0.0.1:%u/o%d%@%@", gProxyPort, o.oid, path,
                   query.length ? [@"?" stringByAppendingString:query] : @""];
    NSURL *p = [NSURL URLWithString:s];
    if (p && outOrigin) *outOrigin = o;
    return p;
}

#pragma mark - Hooks

static IMP VFHook(Class c, SEL sel, IMP imp) {
    Method m = class_getInstanceMethod(c, sel);
    if (!m) {
        VFLog(@"hook: %s not found on %s", sel_getName(sel), class_getName(c));
        return NULL;
    }
    IMP old = method_getImplementation(m);
    if (!class_addMethod(c, sel, imp, method_getTypeEncoding(m))) {
        old = method_setImplementation(m, imp);
    }
    return old;
}

// -[VLCMedia initWithURL:]
static id (*orig_initWithURL)(id, SEL, NSURL *);
static id hook_initWithURL(id self, SEL _cmd, NSURL *url) {
    VFOrigin *o = nil;
    NSURL *use = nil;
    @try { use = VFProxify(url, &o); } @catch (__unused NSException *e) { use = nil; o = nil; }
    id r = orig_initWithURL(self, _cmd, use ?: url);
    if (r && o) objc_setAssociatedObject(r, kOriginKey, @(o.oid), OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    VFLog(@"VLCMedia initWithURL: %@ -> %@", VFSafeURL(url), use ? @"proxy" : @"direct (không proxy)");
    return r;
}

static void VFCaptureOption(id media, NSString *rawKey, NSString *value) {
    NSString *k = rawKey ?: @"";
    while ([k hasPrefix:@":"] || [k hasPrefix:@"-"]) k = [k substringFromIndex:1];
    k = k.lowercaseString;
    VFLog(@"VLCMedia option %@=%@", k, VFRedact(k, value ?: @""));
    NSNumber *oid = objc_getAssociatedObject(media, kOriginKey);
    if (!oid || !value.length) return;
    @synchronized (gRegistryLock) {
        VFOrigin *o = gOriginsById[oid];
        if (!o) return;
        if ([k isEqualToString:@"http-token"]) o.bearer = value;
        else if ([k isEqualToString:@"http-user"]) o.user = value;
        else if ([k isEqualToString:@"http-pwd"] || [k isEqualToString:@"http-password"]) o.pass = value;
    }
}

// -[VLCMedia addOption:]  ("--key=value" hoặc ":key=value")
static void (*orig_addOption)(id, SEL, NSString *);
static void hook_addOption(id self, SEL _cmd, NSString *opt) {
    @try {
        if ([opt isKindOfClass:[NSString class]]) {
            NSRange r = [opt rangeOfString:@"="];
            if (r.location != NSNotFound) {
                VFCaptureOption(self, [opt substringToIndex:r.location], [opt substringFromIndex:r.location + 1]);
            } else {
                VFCaptureOption(self, opt, @"");
            }
        }
    } @catch (__unused NSException *e) {}
    orig_addOption(self, _cmd, opt);
}

// -[VLCMedia addOptions:]  (NSDictionary)
static void (*orig_addOptions)(id, SEL, id);
static void hook_addOptions(id self, SEL _cmd, id opts) {
    @try {
        if ([opts isKindOfClass:[NSDictionary class]]) {
            [(NSDictionary *)opts enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
                VFCaptureOption(self, [NSString stringWithFormat:@"%@", key], [NSString stringWithFormat:@"%@", val]);
            }];
        }
    } @catch (__unused NSException *e) {}
    orig_addOptions(self, _cmd, opts);
}

#pragma mark - libvlc logger

static id gFileLogger;
static void (*orig_setLoggers)(id, SEL, NSArray *);

static id VFMakeFileLogger(void) {
    if (gFileLogger) return gFileLogger;
    if (VFFlagExists(@"VLCFix.nolog")) return nil;
    Class FL = objc_getClass("VLCFileLogger");
    if (!FL) return nil;
    NSFileHandle *h = VFOpenLogFile(@"VLCFix-libvlc.log", 4 * 1024 * 1024);
    if (!h) return nil;
    SEL initSel = sel_registerName("initWithFileHandle:");
    id obj = ((id (*)(id, SEL))objc_msgSend)((id)FL, sel_registerName("alloc"));
    if (!obj || ![obj respondsToSelector:initSel]) return nil;
    obj = ((id (*)(id, SEL, id))objc_msgSend)(obj, initSel, h);
    SEL lvl = sel_registerName("setLevel:");
    if (obj && [obj respondsToSelector:lvl]) {
        ((void (*)(id, SEL, NSUInteger))objc_msgSend)(obj, lvl, 3); // debug
    }
    gFileLogger = obj;
    return obj;
}

static void hook_setLoggers(id self, SEL _cmd, NSArray *loggers) {
    NSArray *use = loggers;
    @try {
        id fl = VFMakeFileLogger();
        if (fl && ![loggers containsObject:fl]) {
            use = loggers ? [loggers arrayByAddingObject:fl] : @[fl];
        }
    } @catch (__unused NSException *e) { use = loggers; }
    orig_setLoggers(self, _cmd, use);
}

static BOOL gMediaHooked, gLibHooked;

static void VFTryInstall(void) {
    @synchronized ([NSObject class]) {
        if (!gMediaHooked) {
            Class m = objc_getClass("VLCMedia");
            if (m) {
                orig_initWithURL = (id (*)(id, SEL, NSURL *))VFHook(m, sel_registerName("initWithURL:"), (IMP)hook_initWithURL);
                orig_addOption = (void (*)(id, SEL, NSString *))VFHook(m, sel_registerName("addOption:"), (IMP)hook_addOption);
                orig_addOptions = (void (*)(id, SEL, id))VFHook(m, sel_registerName("addOptions:"), (IMP)hook_addOptions);
                gMediaHooked = (orig_initWithURL != NULL);
                VFLog(@"VLCMedia hooks installed: init=%d addOption=%d addOptions=%d",
                      orig_initWithURL != NULL, orig_addOption != NULL, orig_addOptions != NULL);
            }
        }
        if (!gLibHooked) {
            Class l = objc_getClass("VLCLibrary");
            if (l) {
                orig_setLoggers = (void (*)(id, SEL, NSArray *))VFHook(l, sel_registerName("setLoggers:"), (IMP)hook_setLoggers);
                gLibHooked = YES;
                VFLog(@"VLCLibrary setLoggers hook installed=%d", orig_setLoggers != NULL);
            }
        }
    }
}

// Nếu app không tự đặt logger, ta tự gắn sau vài giây.
static void VFEnsureLibLogger(void) {
    if (gFileLogger || VFFlagExists(@"VLCFix.nolog")) return;
    Class l = objc_getClass("VLCLibrary");
    if (!l) return;
    SEL shared = sel_registerName("sharedLibrary");
    if (![(id)l respondsToSelector:shared]) return;
    id lib = ((id (*)(id, SEL))objc_msgSend)((id)l, shared);
    if (!lib) return;
    id fl = VFMakeFileLogger();
    if (fl) {
        ((void (*)(id, SEL, NSArray *))objc_msgSend)(lib, sel_registerName("setLoggers:"), @[fl]);
        VFLog(@"libvlc file logger attached by VLCFix");
    }
}

__attribute__((constructor)) static void VFInit(void) {
    @autoreleasepool {
        gRegistryLock = [[NSObject alloc] init];
        gOriginsByKey = [NSMutableDictionary dictionary];
        gOriginsById = [NSMutableDictionary dictionary];
        VFSetupLogging();
        VFLog(@"VLCFix loaded, pid=%d", getpid());
        VFTryInstall();
        for (int i = 1; i <= 10; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)i * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                VFTryInstall();
            });
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            VFEnsureLibLogger();
        });
    }
}
