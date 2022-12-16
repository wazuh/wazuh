import pytest

@pytest.mark.skip("Not implemented yet")
def test_AWSWAFBucket__init__():
    pass

# Extracted from the previous tests. To be reviewed/reworked
# @pytest.mark.parametrize('log_file, skip_on_error', [
#     (f'{logs_path}/WAF/aws-waf', False),
#     (f'{logs_path}/WAF/aws-waf', True),
#     (f'{logs_path}/WAF/aws-waf-invalid-json', True),
#     (f'{logs_path}/WAF/aws-waf-wrong-structure', True),
# ])
# def test_AWSWAFBucket_load_information_from_file(log_file: str, aws_waf_bucket: AWSWAFBucket,
#                                             skip_on_error: bool):
#     """
#     Test AWSWAFBucket's implementation of the load_information_from_file method.
#
#     Parameters
#     ----------
#     log_file : str
#         File that should be decompressed.
#     aws_waf_bucket : AWSWAFBucket
#         Instance of the AWSWAFBucket class.
#     skip_on_error : bool
#         If the skip_on_error is disabled or not.
#     """
#     aws_waf_bucket.skip_on_error = skip_on_error
#     with open(log_file, 'rb') as f:
#         aws_waf_bucket.client.get_object.return_value.__getitem__.return_value = f
#         aws_waf_bucket.load_information_from_file(log_file)
#
#
# @pytest.mark.parametrize('log_file, skip_on_error, expected_exception', [
#     (f'{logs_path}/WAF/aws-waf-invalid-json', False, SystemExit),
#     (f'{logs_path}/WAF/aws-waf-wrong-structure', False, SystemExit),
# ])
# def test_AWSWAFBucket_load_information_from_file_ko(
#         log_file: str, skip_on_error: bool,
#         expected_exception: Exception,
#         aws_waf_bucket: AWSWAFBucket):
#     """
#     Test that AWSWAFBucket's implementation of the load_information_from_file method raises
#     an exception when called with invalid arguments.
#
#     Parameters
#     ----------
#     log_file : str
#         File that should be decompressed.
#     skip_on_error : bool
#         If the skip_on_error is disabled or not.
#     expected_exception : Exception
#         Exception that should be raised.
#     aws_waf_bucket : AWSWAFBucket
#         Instance of the AWSWAFBucket class.
#     """
#     aws_waf_bucket.skip_on_error = skip_on_error
#     with open(log_file, 'rb') as f, \
#          pytest.raises(expected_exception):
#         aws_waf_bucket.client.get_object.return_value.__getitem__.return_value = f
#         aws_waf_bucket.load_information_from_file(log_file)
