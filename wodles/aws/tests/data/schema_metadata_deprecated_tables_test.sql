CREATE TABLE 'metadata' (
    key 'text' NOT NULL,
    value 'text' NOT NULL,
    PRIMARY KEY (key, value));

CREATE TABLE 'log_progress' (
    key 'text' NOT NULL,
    value 'text' NOT NULL,
    PRIMARY KEY (key, value));

CREATE TABLE 'trail_progress' (
    key 'text' NOT NULL,
    value 'text' NOT NULL,
    PRIMARY KEY (key, value));
