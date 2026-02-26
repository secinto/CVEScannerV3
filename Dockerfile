FROM str0ke/nmap
RUN apk add --no-cache lua5.4-sql-sqlite3 && ln -s /usr/lib/lua /usr/local/lib/lua
COPY extra /CVEScannerV3/extra
COPY cvescannerv3.nse /CVEScannerV3
WORKDIR /CVEScannerV3
ENTRYPOINT ["nmap", "--script", "cvescannerv3", "-sV"]
