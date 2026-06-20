FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

COPY cti-mcp /usr/local/bin/cti-mcp
RUN chmod +x /usr/local/bin/cti-mcp

ENV CTI_MCP_DB_PATH=/data/cti.db
ENV CTI_MCP_LOG_LEVEL=info

VOLUME /data

ENTRYPOINT ["cti-mcp"]
CMD ["serve"]
