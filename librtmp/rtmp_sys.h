#ifndef __RTMP_SYS_H__
#define __RTMP_SYS_H__
/*
 *      Copyright (C) 2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER	/* MSVC */
#define snprintf _snprintf
#define strcasecmp stricmp
#define strncasecmp strnicmp
#define vsnprintf _vsnprintf
#endif

#define GetSockError()	WSAGetLastError()
#define SetSockError(e)	WSASetLastError(e)
#define setsockopt(a,b,c,d,e)	(setsockopt)(a,b,c,(const char *)d,(int)e)
#define EWOULDBLOCK	WSAETIMEDOUT	/* we don't use nonblocking, but we do use timeouts */
#define sleep(n)	Sleep(n*1000)
#define msleep(n)	Sleep(n)
#define SET_RCVTIMEO(tv,s)	int tv = s*1000
#else /* !_WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/times.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define GetSockError()	errno
#define SetSockError(e)	errno = e
#undef closesocket
#define closesocket(s)	close(s)
#define msleep(n)	usleep(n*1000)
#define SET_RCVTIMEO(tv,s)	struct timeval tv = {s,0}
#endif

#include "rtmp.h"

#ifdef USE_POLARSSL
#include <polarssl/version.h>
#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/havege.h>
#if POLARSSL_VERSION_NUMBER < 0x01010000
#define havege_random	havege_rand
#endif
#if POLARSSL_VERSION_NUMBER >= 0x01020000
#define	SSL_SET_SESSION(S,resume,timeout,ctx)	ssl_set_session(S,ctx)
#else
#define	SSL_SET_SESSION(S,resume,timeout,ctx)	ssl_set_session(S,resume,timeout,ctx)
#endif
typedef struct tls_ctx {
	havege_state hs;
	ssl_session ssn;
} tls_ctx;
typedef struct tls_server_ctx {
	havege_state *hs;
	x509_cert cert;
	rsa_context key;
	ssl_session ssn;
	const char *dhm_P, *dhm_G;
} tls_server_ctx;

#define TLS_CTX tls_ctx *
#define TLS_client(ctx,s)	s = malloc(sizeof(ssl_context)); ssl_init(s);\
	ssl_set_endpoint(s, SSL_IS_CLIENT); ssl_set_authmode(s, SSL_VERIFY_NONE);\
	ssl_set_rng(s, havege_random, &ctx->hs);\
	ssl_set_ciphersuites(s, ssl_default_ciphersuites);\
	SSL_SET_SESSION(s, 1, 600, &ctx->ssn)
#define TLS_server(ctx,s)	s = malloc(sizeof(ssl_context)); ssl_init(s);\
	ssl_set_endpoint(s, SSL_IS_SERVER); ssl_set_authmode(s, SSL_VERIFY_NONE);\
	ssl_set_rng(s, havege_random, ((tls_server_ctx*)ctx)->hs);\
	ssl_set_ciphersuites(s, ssl_default_ciphersuites);\
	SSL_SET_SESSION(s, 1, 600, &((tls_server_ctx*)ctx)->ssn);\
	ssl_set_own_cert(s, &((tls_server_ctx*)ctx)->cert, &((tls_server_ctx*)ctx)->key);\
	ssl_set_dh_param(s, ((tls_server_ctx*)ctx)->dhm_P, ((tls_server_ctx*)ctx)->dhm_G)
#define TLS_setfd(s,fd)	ssl_set_bio(s, net_recv, &fd, net_send, &fd)
#define TLS_connect(s)	ssl_handshake(s)
#define TLS_accept(s)	ssl_handshake(s)
#define TLS_read(s,b,l)	ssl_read(s,(unsigned char *)b,l)
#define TLS_write(s,b,l)	ssl_write(s,(unsigned char *)b,l)
#define TLS_shutdown(s)	ssl_close_notify(s)
#define TLS_close(s)	ssl_free(s); free(s)

#elif defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
typedef struct tls_ctx {
	gnutls_certificate_credentials_t cred;
	gnutls_priority_t prios;
} tls_ctx;
#define TLS_CTX	tls_ctx *
#define TLS_client(ctx,s)	gnutls_init((gnutls_session_t *)(&s), GNUTLS_CLIENT); gnutls_priority_set(s, ctx->prios); gnutls_credentials_set(s, GNUTLS_CRD_CERTIFICATE, ctx->cred)
#define TLS_server(ctx,s)	gnutls_init((gnutls_session_t *)(&s), GNUTLS_SERVER); gnutls_priority_set_direct(s, "NORMAL", NULL); gnutls_credentials_set(s, GNUTLS_CRD_CERTIFICATE, ctx)
#define TLS_setfd(s,fd)	gnutls_transport_set_ptr(s, (gnutls_transport_ptr_t)(long)fd)
#define TLS_connect(s)	gnutls_handshake(s)
#define TLS_accept(s)	gnutls_handshake(s)
#define TLS_read(s,b,l)	gnutls_record_recv(s,b,l)
#define TLS_write(s,b,l)	gnutls_record_send(s,b,l)
#define TLS_shutdown(s)	gnutls_bye(s, GNUTLS_SHUT_RDWR)
#define TLS_close(s)	gnutls_deinit(s)

#elif defined(USE_SECURETRANSPORT)
#include <Security/Security.h>
#include <Security/SecureTransport.h>
static OSStatus st_read(SSLConnectionRef cxn, void *data, size_t *dataLength)
{
    int fd = (int)cxn, totalRead = 0, toRead = *dataLength;
    while (toRead > 0) {
        int ret = read(fd, data, toRead);
        printf("SecureTransport st_read %lu ret %d\n", *dataLength, ret);
        if (ret <= 0) {
            switch (ret) {
            case 0: return errSecIO; // EOF
            case ECONNRESET: return errSSLClosedAbort;
            case EAGAIN: return errSSLWouldBlock;
            default: {
                char err[64];
                strerror_r(err, sizeof(err), errno);
                fprintf(stderr, "Unknown return %d: %s\n", ret, err);
            }
            }
        }
        totalRead += ret;
        data += ret;
        toRead -= ret;
    }
    *dataLength = totalRead;
    return errSecSuccess;
}
static OSStatus st_write(SSLConnectionRef cxn, const void *data, size_t *dataLength)
{
    int fd = (int)cxn;
    int ret = write(fd, data, *dataLength);
    *dataLength = ret;
    if (ret <= 0) return ret;
    return noErr;
}
static void st_io(SSLContextRef ssl, int fd)
{
    OSStatus r1 = SSLSetIOFuncs(ssl, st_read, st_write);
    OSStatus r2 = SSLSetConnection(ssl, (SSLConnectionRef)(intptr_t)fd);
    if (r1 != noErr || r2 != noErr) printf("Unable to set IO for SSL\n");
}
static size_t st_ssl_read(SSLContextRef ssl, void *data, size_t len)
{
    size_t processed;
    OSErr ret = SSLRead(ssl, data, len, &processed);
    printf("st_ssl_read: %lu bytes returning %d\n", len, ret);
    if (noErr != ret) return ret;
    return processed;
}
static size_t st_ssl_write(SSLContextRef ssl, const char *data, size_t len)
{
    size_t processed;
    OSErr ret = SSLWrite(ssl, data, len, &processed);
    printf("st_ssl_write: %lu bytes returning %d\n", len, ret);
    if (noErr != ret) return ret;
    if (noErr != ret) return ret;
    return processed;
}
#define TLS_CTX SSLContextRef
#define TLS_client(ctx, s) (s) = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType)
#define TLS_server(ctx, s)
#define TLS_setfd(s, fd) st_io(s, fd)
#define TLS_connect(s) SSLHandshake(s)
#define TLS_accept
#define TLS_read(s,b,l) st_ssl_read(s, b, l)
#define TLS_write(s,b,l) st_ssl_write(s, b, l)
#define TLS_shutdown(s)
#define TLS_close(s) SSLClose(s)

#else	/* USE_OPENSSL */
#define TLS_CTX	SSL_CTX *
#define TLS_client(ctx,s)	s = SSL_new(ctx)
#define TLS_server(ctx,s)	s = SSL_new(ctx)
#define TLS_setfd(s,fd)	SSL_set_fd(s,fd)
#define TLS_connect(s)	SSL_connect(s)
#define TLS_accept(s)	SSL_accept(s)
#define TLS_read(s,b,l)	SSL_read(s,b,l)
#define TLS_write(s,b,l)	SSL_write(s,b,l)
#define TLS_shutdown(s)	SSL_shutdown(s)
#define TLS_close(s)	SSL_free(s)

#endif
#endif
