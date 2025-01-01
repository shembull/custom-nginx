FROM alpine:latest AS builder

RUN adduser -S nginx \
    && addgroup -S nginx

ENV PCRE_V=10.44
ENV ZLIB_V=1.3.1
ENV ZLIB_D=131
ENV OPENSSL_V=3.4.0
ENV NGINX_V=1.27.3

# Build custom nginx server
RUN set -x \
    && apk update \
    && apk add curl tar git \
    && mkdir /build \
    && cd /build \
    && curl -L https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$(echo $PCRE_V)/pcre2-$(echo $PCRE_V).tar.gz -o pcre.tar.gz \
    && curl -L https://www.zlib.net/zlib$(echo $ZLIB_D).zip -o zlib.zip \
    && curl -L https://www.openssl.org/source/openssl-$(echo $OPENSSL_V).tar.gz -o openssl.tar.gz \
    && tar -xzf pcre.tar.gz \
    && unzip zlib.zip \
    && tar -xzf openssl.tar.gz \
    && rm pcre.tar.gz zlib.zip openssl.tar.gz \
    && git clone https://github.com/stnoonan/spnego-http-auth-nginx-module.git \
    && git clone --recurse-submodules https://github.com/google/ngx_brotli \
    && apk del --purge curl tar git

RUN set -x \
    && apk update \
    && apk add curl tar make cmake g++ krb5-dev linux-headers perl automake autoconf \
    && cd /build \
    && curl -L https://nginx.org/download/nginx-$(echo $NGINX_V).tar.gz -o nginx.tar.gz \
    && tar -zxf nginx.tar.gz \
    && rm nginx.tar.gz \
    && cd ngx_brotli/deps/brotli \
    && mkdir out && cd out \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_CXX_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_INSTALL_PREFIX=./installed .. \
    && cmake --build . --config Release --target brotlienc \
    && cd ../../../.. \
    && cd nginx-$(echo $NGINX_V)/ \
    && sed -i 's/static u_char ngx_http_server_string\[\] = "Server: nginx" CRLF/static u_char ngx_http_server_string\[\] = "Server: BonsaiWeb" CRLF/g' src/http/ngx_http_header_filter_module.c \
    && sed -i 's/static u_char ngx_http_server_full_string\[\] = "Server: " NGINX_VER CRLF/static u_char ngx_http_server_full_string\[\] = "Server: BonsaiWeb" CRLF/g' src/http/ngx_http_header_filter_module.c \
    && sed -i 's/static u_char ngx_http_server_build_string\[\] = "Server: " NGINX_VER_BUILD CRLF/static u_char ngx_http_server_build_string\[\] = "Server: BonsaiWeb" CRLF/g' src/http/ngx_http_header_filter_module.c \
    && export CFLAGS="-m64 -march=native -mtune=native -Ofast -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" \
    && export LDFLAGS="-m64 -Wl,-s -Wl,-Bsymbolic -Wl,--gc-sections" \
    && ./configure --prefix=/usr/share/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/run/nginx.pid \
        --lock-path=/var/lock/nginx.lock \
        --user=nginx \
        --group=nginx \
        --build=Alpine \
        --http-client-body-temp-path=/var/lib/nginx/body \
        --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
        --http-proxy-temp-path=/var/lib/nginx/proxy \
        --http-scgi-temp-path=/var/lib/nginx/scgi \
        --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
        --with-openssl=../openssl-$(echo $OPENSSL_V) \
        --with-openssl-opt=enable-ec_nistp_64_gcc_128 \
        --with-openssl-opt=no-nextprotoneg \
        --with-openssl-opt=no-weak-ssl-ciphers \
        --with-openssl-opt=no-ssl3 \
        --with-pcre=../pcre2-$(echo $PCRE_V) \
        --with-pcre-jit \
        --with-zlib=../zlib-$(echo $ZLIB_V) \
        --with-compat \
        --with-file-aio \
        --with-threads \
        --with-http_addition_module \
        --with-http_auth_request_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_mp4_module \
        --with-http_random_index_module \
        --with-http_realip_module \
        --with-http_slice_module \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_stub_status_module \
        --with-http_v2_module \
        --with-http_secure_link_module \
        --with-mail \
        --with-mail_ssl_module \
        --with-stream \
        --with-stream_realip_module \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-debug \
        --add-module=../spnego-http-auth-nginx-module \
        --add-module=../ngx_brotli \
        --with-cc-opt='-g -O2 -fPIC -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
        --with-ld-opt='-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now' \
    && make \
    && make install \
    && mkdir -p /var/lib/nginx \
    && cd / \
    && rm -r /build \
    && apk del --purge curl tar make g++ linux-headers perl automake autoconf

FROM alpine:latest

COPY --from=builder /usr/sbin/nginx /usr/sbin/
COPY --from=builder /usr/share/nginx/html/* /usr/share/nginx/html/
COPY --from=builder /etc/nginx/* /etc/nginx/

RUN \
    apk update \
    # Bring in tzdata so users could set the timezones through the environment
    # variables
    && apk add --no-cache tzdata \
    \
    && apk add --no-cache \
    pcre \
    libgcc \
    krb5 \
    && addgroup -S nginx \
    && adduser -D -S -h /var/cache/nginx -s /sbin/nologin -G nginx nginx \
    && mkdir -p /var/lib/nginx \
    # forward request and error logs to docker log collector
    && mkdir -p /var/log/nginx \
    && mkdir -p /var/lib/nginx/body \
    && touch /var/log/nginx/access.log /var/log/nginx/error.log \
    && chown nginx: /var/log/nginx/access.log /var/log/nginx/error.log \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

STOPSIGNAL SIGTERM

EXPOSE 80/tcp
EXPOSE 443/tcp

ENTRYPOINT ["/usr/sbin/nginx"]

CMD ["-g", "daemon off;"]
