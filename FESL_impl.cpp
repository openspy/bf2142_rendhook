#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#include "CDetour.h"
#include <stdint.h>

#include <openssl/ssl.h>

#define SERVER_HOSTNAME "bf2142-pc.openspy.net"
#define SERVER_PORT 18301


SSL_CTX* g_ssl_ctx = NULL;

SSL* g_ssl;
BIO* g_read_bio;
BIO* g_write_bio;

typedef struct _SSLStateInfo {
	uint32_t unkptr_1;
	uint32_t unkptr_2;
	uint32_t send_buffer_cursor;
	uint32_t current_send_len;
	uint32_t unkptr_5;
	uint32_t recv_current_len;
	uint32_t recv_expected_len;
	uint32_t recv_buffer_cursor;
	uint8_t unk3[2232];
	uint8_t send_buffer[16384];
	uint8_t recv_buffer[16384];
} SSLStateInfo;

typedef struct _SOCKET_Handler {
	int (*unk_callback_1)(struct _SOCKET_Handler*);
	int (*unk_callback_2)(struct _SOCKET_Handler*);
	int (*unk_callback_3)(struct _SOCKET_Handler*);
	int (*unk_callback_4)(struct _SOCKET_Handler*);
	uint8_t test[32];
} SOCKETHandler;

typedef struct _FESLSOCKET {
	uint32_t unk[6];
	uint32_t socket;
} FESLSOCKET;

typedef struct _FESLCtx {
	struct _FESLSOCKET *fesl_socket;
	struct _SOCKET_Handler* socket_handler;
	uint32_t unk11[4];
	uint32_t unk_socket_thing;
	uint32_t unk[60];
	struct sockaddr_in resolved_address;
	uint32_t connection_state;
	uint32_t got_error;
	struct _SSLStateInfo* ssl_state;
} FESLCtx;


void show_dump(unsigned char* data, unsigned int len, FILE* stream) {
	static const char       hex[] = "0123456789abcdef";
	static unsigned char    buff[67];   /* HEX  CHAR\n */
	unsigned char           chr,
		* bytes,
		* p,
		* limit,
		* glimit = data + len;

	memset(buff + 2, ' ', 48);

	while (data < glimit) {
		limit = data + 16;
		if (limit > glimit) {
			limit = glimit;
			memset(buff, ' ', 48);
		}

		p = buff;
		bytes = p + 50;
		while (data < limit) {
			chr = *data;
			*p++ = hex[chr >> 4];
			*p++ = hex[chr & 15];
			p++;
			*bytes++ = ((chr < ' ') || (chr >= 0x7f)) ? '.' : chr;
			data++;
		}
		*bytes++ = '\n';

		fwrite(buff, bytes - buff, 1, stream);
	}
}


extern FILE* console_fd;

class IFESL {
public:
	virtual void unknownFunc1(char a2) = 0;
	virtual int setConnectionDetails(const char *hostname, int a2, int a3) = 0;
	virtual int buildFESLHostname(const char* a2, int a3, const char* a4, int a5, int a6) = 0;
};

class FESLImpl {
public:
	void unknownFunc1(char a2) {

	}
	int setConnectionDetails(const char* hostname, int a2, int a3) {
		return 0;
	}
	int buildFESLHostname(const char* a2, int a3, const char* a4, int a5, int a6) {
		IFESL* real_fesl = (IFESL*)this;
		return real_fesl->setConnectionDetails(SERVER_HOSTNAME, SERVER_PORT, a6);
	}
};


int spy_SSL_LogicThread(FESLCtx* ctx) {
	int (*real_func)(FESLCtx*) = (int (*)(FESLCtx*))0x861190;
	/*fprintf(console_fd, "SSL_LogicThread: %p\n", a1);
	int *state = (int*)((int)a1 + 284);
	fprintf(console_fd, "SSL state pre: %d\n", *state);
	int r = real_func(a1);
	fprintf(console_fd, "SSL_LogicThread post: %d, result: %d\n", *state, r);
	fflush(console_fd);*/
	
	if (ctx->connection_state == 30) {
		//fprintf(console_fd, "resolve address: %08x - %08x\n", ctx->resolved_address.sin_addr.S_un.S_addr, ctx->resolved_address.sin_port);
		if (ctx->ssl_state->current_send_len) {
			fprintf(console_fd, "SEND\n");
			show_dump(&ctx->ssl_state->send_buffer[ctx->ssl_state->send_buffer_cursor], ctx->ssl_state->current_send_len - ctx->ssl_state->send_buffer_cursor, console_fd);
			fflush(console_fd);
		}
	}
	int r = real_func(ctx);
	if (ctx->connection_state == 30) {
		if (ctx->ssl_state->recv_current_len) {
			fprintf(console_fd, "RECV\n");
			show_dump(ctx->ssl_state->recv_buffer, ctx->ssl_state->recv_current_len, console_fd);
			fflush(console_fd);
		}
		
		
	}
	else {
		fprintf(console_fd, "state: %d\n", ctx->connection_state);
	}
	fflush(console_fd);
	return r;
}


void SSL_Flush(FESLCtx* ctx) {
	int ssl_write_sz = BIO_pending(g_write_bio);
	if (ssl_write_sz == 0) {
		return;
	}
	if (ssl_write_sz > 0) {
		BIO_read(g_write_bio, &ctx->ssl_state->send_buffer, ssl_write_sz);

		int r = send(ctx->fesl_socket->socket, (const char*)&ctx->ssl_state->send_buffer, ssl_write_sz, 0);
		if (r < 0) {
			ctx->connection_state = 4099;
			ctx->got_error = 1;
			return;
		}
	}
}
void SSL_Read(FESLCtx* ctx) {
	int r = recv(ctx->fesl_socket->socket, (char*)&ctx->ssl_state->recv_buffer, sizeof(ctx->ssl_state->recv_buffer), 0);
	
	if (r < 0) {
		int wserr = WSAGetLastError();
		if (wserr != WSAEWOULDBLOCK) {
			ctx->connection_state = 4097;
			ctx->got_error = 1;
		}
	}
	else if (r > 0) {
		BIO_write(g_read_bio, (char*)&ctx->ssl_state->recv_buffer, r);
		if (!SSL_is_init_finished(g_ssl)) {
			SSL_Flush(ctx);
		}
	}
}

int SSL_LogicThread(FESLCtx* ctx) {
	fprintf(console_fd, "SSL_LogicThread: %d - %d\n", ctx->connection_state, ctx->fesl_socket->socket);
	fflush(console_fd);
	if (ctx->connection_state == 2) {
		//unsigned long mode = 1; // 1 for non-blocking, 0 for blocking
		//if (ioctlsocket(ctx->fesl_socket->socket, FIONBIO, &mode) != 0) {
		//	fprintf(console_fd, "Changed to non-blocking failure\n");
		//	ctx->connection_state = 4099;
		//	ctx->got_error = 1;
		//	return ctx->connection_state;
		//}
		fprintf(console_fd, "Changed to non-blocking\n");

		ctx->connection_state = 3;
	}
	else if (ctx->connection_state == 3) { //need to do connection
		int r = connect(ctx->fesl_socket->socket, (const sockaddr*)&ctx->resolved_address, sizeof(const sockaddr));
		fprintf(console_fd, "connect: %d\n", r);
		if (r < 0) {
			int lastErr = WSAGetLastError();
			fprintf(console_fd, "conn last err: %d\n", lastErr);
			if (lastErr == WSAEWOULDBLOCK || lastErr == WSAEALREADY || lastErr == WSAEINVAL) {
				return ctx->connection_state;
			}
			else if (lastErr == WSAEISCONN) {
				ctx->connection_state = 4;

			}
			else {
				ctx->connection_state = 4099;
				ctx->got_error = 1;
			}
		}
		else {
			ctx->connection_state = 4;
		}
	}
	else if (ctx->connection_state == 4) { //init SSL connection
		g_ssl = SSL_new(g_ssl_ctx);
		g_read_bio = BIO_new(BIO_s_mem());
		g_write_bio = BIO_new(BIO_s_mem());
		BIO_set_nbio(g_read_bio, 1);
		BIO_set_nbio(g_write_bio, 1);


		SSL_set_tlsext_host_name(g_ssl, SERVER_HOSTNAME);
		SSL_set1_host(g_ssl, SERVER_HOSTNAME);


		SSL_set_bio(g_ssl, g_read_bio, g_write_bio);
		SSL_set_connect_state(g_ssl);

		ctx->connection_state = 5;
		//SSL_connect(g_ssl);
	}
	else if (ctx->connection_state == 5) { //in handshake state

		int n = SSL_do_handshake(g_ssl);

		int err = SSL_get_error(g_ssl, n);
		if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			SSL_Flush(ctx);
			SSL_Read(ctx);
		}
		else if (n == 1) {
			ctx->connection_state = 30;
		}
		else {
			ctx->connection_state = 4097;
			ctx->got_error = 1;
		}
		
	}
	else if (ctx->connection_state == 30) { //read SSL incoming data
		int recvbuf[4096];
		while (true) {
			int r = recv(ctx->fesl_socket->socket, (char*)&recvbuf[0], sizeof(recvbuf), 0);
			if (r <= 0) {
				break;
			}
			BIO_write(g_read_bio, (char*)&recvbuf[0], r);
		}
		int read_len = sizeof(ctx->ssl_state->recv_buffer) - ctx->ssl_state->recv_buffer_cursor;
		while (true) {
			int sr = SSL_read(g_ssl, (void*)&ctx->ssl_state->recv_buffer[ctx->ssl_state->recv_expected_len], read_len);
			if (sr <= 0) {
				break;
			}
			ctx->ssl_state->recv_expected_len += sr;
			show_dump((unsigned char*)&ctx->ssl_state->recv_buffer[ctx->ssl_state->recv_buffer_cursor], sr, console_fd);
		}
		fflush(console_fd);
	}
	SSL_Flush(ctx);
	return ctx->connection_state;
}

int fesl_SSL_Send(FESLCtx* ctx, char* buf, int len) {
	int result = -1;
	if (len < 0) {
		len = strlen(buf);
	}
	if (ctx->connection_state == 30) {
		int r = SSL_write(g_ssl, buf, len);
		result = r;
		SSL_Flush(ctx);
	}
	return result;
}

int fesl_SSL_recv(FESLCtx* ctx, char* buf, int len) {
	int result = 0;
	if (ctx->connection_state == 30) {
		SSL_LogicThread(ctx);
		if (ctx->ssl_state->recv_expected_len == 0) {
			return 0;
		}
		int read_len = ctx->ssl_state->recv_expected_len - ctx->ssl_state->recv_buffer_cursor;
		if (read_len > len) {
			read_len = len;
		}
		memcpy(buf, (const void*)&ctx->ssl_state->recv_buffer[ctx->ssl_state->recv_buffer_cursor], read_len);
		ctx->ssl_state->recv_buffer_cursor += read_len;
		if (ctx->ssl_state->recv_buffer_cursor >= ctx->ssl_state->recv_expected_len) {
			ctx->ssl_state->recv_buffer_cursor = 0;
			ctx->ssl_state->recv_expected_len = 0;
			ctx->ssl_state->recv_current_len = 0;
		}
		result = read_len;
		show_dump((unsigned char *)buf, read_len, console_fd);
		
	}
	
	fflush(console_fd);
	if (result > 0 && result < len)
		buf[result] = 0;
	return result;
}

//int verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
//	return 1;
//}
void install_fesl_patches() {
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();



	g_ssl_ctx = SSL_CTX_new(TLS_method());
	//SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL); //call this to enable verification
	//SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_3_VERSION);
	//SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_3_VERSION);



	SSL_CTX_set_cipher_list(g_ssl_ctx, "ALL");
	SSL_CTX_set_options(g_ssl_ctx, SSL_OP_ALL);


	DWORD old;

	void* feslResolveFuncAddr = (void*)0x9C5BE8;
	auto ourFeslResolveAddr = &FESLImpl::buildFESLHostname;

	VirtualProtect(feslResolveFuncAddr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
	WriteProcessMemory(GetCurrentProcess(), feslResolveFuncAddr, &ourFeslResolveAddr, sizeof(void*), NULL);

	VirtualProtect(feslResolveFuncAddr, sizeof(void*), old, &old);
	FlushInstructionCache(GetCurrentProcess(), feslResolveFuncAddr, sizeof(void*));

	void* ssl_logic_calls[] = {
		(void*)0x0083DC32,
		(void*)0x0085E1EC,
		(void*)0x0085E2B6,
		(void*)0x008615BE,
		(void*)0x00861631
	};

	CDetour detour;
	for (int i = 0; i < sizeof(ssl_logic_calls) / sizeof(void*); i++) {
		detour.Create((BYTE*)ssl_logic_calls[i], (const BYTE*)SSL_LogicThread, DETOUR_TYPE_CALL_FUNC, 5);
	}


	void* ssl_send_data_calls[] = {
		(void*)0x0083D6D6,
		(void*)0x0083D8D1,
		(void*)0x0083DCB6,
		(void*)0x0085E2DA
	};
	for (int i = 0; i < sizeof(ssl_send_data_calls) / sizeof(void*); i++) {
		detour.Create((BYTE*)ssl_send_data_calls[i], (const BYTE*)fesl_SSL_Send, DETOUR_TYPE_CALL_FUNC, 5);
	}


	void* ssl_recv_data_calls[] = {
		(void*)0x0083D706,
		(void*)0x0083DCDB,
		(void*)0x0083DD8F,
		(void*)0x0083DE7F,
		(void*)0x0085E32C,
		(void*)0x0085E3E6,
	};
	for (int i = 0; i < sizeof(ssl_recv_data_calls) / sizeof(void*); i++) {
		detour.Create((BYTE*)ssl_recv_data_calls[i], (const BYTE*)fesl_SSL_recv, DETOUR_TYPE_CALL_FUNC, 5);
	}

}