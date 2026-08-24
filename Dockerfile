FROM golang:alpine AS builder

WORKDIR /root
COPY go.mod main.go install.sh .
RUN ./install.sh


FROM scratch

COPY --from=builder /root/.local/bin/Proxima /usr/local/bin/Proxima
WORKDIR /root

ENTRYPOINT ["Proxima"]
