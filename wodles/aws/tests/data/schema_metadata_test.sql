CREATE TABLE 'metadata' (
    key 'text' NOT NULL,
    value 'text' NOT NULL,
    PRIMARY KEY (key, value));

INSERT INTO 'metadata' (key, value) VALUES ('version', '0.0.0');
