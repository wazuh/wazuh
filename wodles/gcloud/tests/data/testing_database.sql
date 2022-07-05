PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE test_table (
    project_id 'text' NOT NULL,
    bucket_name 'text' NOT NULL,
    prefix 'text' NULL,
    blob_name 'text' NOT NULL,
    creation_time 'text' NOT NULL,
    PRIMARY KEY (project_id, bucket_name, prefix, blob_name)
);
INSERT INTO test_table VALUES('project_123', 'test_bucket', '', 'blob_file_1', '2021-01-01 12:00:00.123456Z');
INSERT INTO test_table VALUES('project_123', 'test_bucket', '', 'blob_file_2', '2021-01-01 12:00:00.123456Z');
INSERT INTO test_table VALUES('project_123', 'test_bucket_2', '', 'blob_file_1', '2021-01-01 12:00:00.123456Z');
INSERT INTO test_table VALUES('project_123', 'test_bucket_2', '', 'blob_file_2', '2021-01-01 12:00:00.123456Z');
COMMIT;
