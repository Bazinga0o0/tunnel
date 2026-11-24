-- +goose Up
CREATE TABLE reserved_tcp_ports (
    port        INTEGER PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT reserved_tcp_ports_range CHECK (port BETWEEN 1 AND 65535)
);
CREATE INDEX reserved_tcp_ports_user_id_idx ON reserved_tcp_ports (user_id);

-- +goose Down
DROP TABLE reserved_tcp_ports;
