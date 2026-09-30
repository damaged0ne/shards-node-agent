
static __always_inline
int is_http_request(char *buf) {
    char b[16];
    if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 16) {
        return 0;
    }
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T') {
        return 1;
    }
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T') {
        return 1;
    }
    if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E') {
        return 1;
    }
    if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T') {
        return 1;
    }
    if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_http_response(char *buf, __s32 *status) {
    char b[16];
    if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 16) {
        return 0;
    }
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
        return 0;
    }
    if (b[5] < '0' || b[5] > '9') {
        return 0;
    }
    if (b[6] != '.') {
        return 0;
    }
    if (b[7] < '0' || b[7] > '9') {
        return 0;
    }
    if (b[8] != ' ') {
        return 0;
    }
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return 0;
    }
    *status = (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
    return 1;
}

// 1xx responses except for "101 Switching Protocols" are interim: the final response follows.
static __always_inline
int is_http_interim_status(__s32 status) {
    return status >= 100 && status < 200 && status != 101;
}

#define HTTP_100_CONTINUE_SIZE 25 // "HTTP/1.1 100 Continue\r\n\r\n"

static __always_inline
int is_http_100_continue(char *buf) {
    char b[HTTP_100_CONTINUE_SIZE];
    if (bpf_probe_read(&b, sizeof(b), (void *)buf)) {
        return 0;
    }
    return b[9] == '1' && b[10] == '0' && b[11] == '0' && b[12] == ' ' &&
           b[13] == 'C' && b[20] == 'e' &&
           b[21] == '\r' && b[22] == '\n' && b[23] == '\r' && b[24] == '\n';
}
