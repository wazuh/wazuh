
CREATE TABLE 'cloudtrail' (
    bucket_path 'text' NOT NULL,
    aws_account_id 'text' NOT NULL,
    aws_region 'text' NOT NULL,
    log_key 'text' NOT NULL,
    processed_date 'text' NOT NULL,
    created_date 'integer' NOT NULL,
    PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));
