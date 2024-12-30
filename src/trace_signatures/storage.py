from urllib.parse import urlparse, parse_qs
import boto3
from botocore import UNSIGNED
from botocore.config import Config
import botocore
import json
from loguru import logger

def get_s3_client(store_url, anon=False):
    """
    Create an S3 client from the store URL

    Args:
        store_url (str): The S3 store URL
        anon (bool): If True, use anonymous access without credentials
    """
    logger.debug(f"Creating S3 client for URL: {store_url}")
    try:
        parsed_url = urlparse(store_url)
        if not parsed_url.scheme.startswith('s3'):
            raise ValueError(f"Unsupported store URL scheme: {parsed_url.scheme}")

        bucket = parsed_url.path.split('?')[0].strip('/')
        if not bucket:
            bucket = parsed_url.netloc.split('?')[0]

        query_params = parse_qs(parsed_url.query)
        endpoint_url = query_params.get('endpoint', [None])[0]

        if anon:
            logger.debug("Using anonymous access (unsigned requests)")
            config = Config(
                signature_version=UNSIGNED,
                s3={'addressing_style': 'path'}
            )
        else:
            logger.debug("Using default credential chain")
            config = Config(s3={'addressing_style': 'path'})

        return {
            'client': boto3.client(
                's3',
                endpoint_url=endpoint_url,
                config=config
            ),
            'bucket': bucket
        }
    except Exception:
        logger.exception("error creating S3 client")
        raise

def get_existing_signatures(s3_client, bucket: str, key: str):
    """Get existing signatures from S3"""
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = json.loads(response['Body'].read())
        etag = response['ETag'].strip('"')
        return content, etag
    except botocore.exceptions.ClientError as err:
        if err.response['Error']['Code'] == 'NoSuchKey':
            return None, None
        raise
    except Exception:
        logger.exception("error fetching existing signatures")
        raise

def upload_signature(store_url, input_hash, signature):
    """Upload signature to S3-compatible storage"""
    try:
        s3_info = get_s3_client(store_url)
        s3_client = s3_info['client']
        bucket = s3_info['bucket']
        key = f"traces/{input_hash}"

        max_retries = 5
        retry_count = 0

        while retry_count < max_retries:
            try:
                existing_content, etag = get_existing_signatures(
                    s3_client, bucket, key)

                if existing_content is None:
                    new_content = {"signatures": [signature]}
                    s3_client.put_object(
                        Bucket=bucket,
                        Key=key,
                        Body=json.dumps(new_content),
                        ContentType='application/json'
                    )
                    break
                elif signature not in existing_content["signatures"]:
                    new_content = {
                        "signatures": existing_content["signatures"] + [signature]
                    }
                    try:
                        s3_client.put_object(
                            Bucket=bucket,
                            Key=key,
                            Body=json.dumps(new_content),
                            ContentType='application/json',
                            Metadata={'If-Match': etag}
                        )
                        break
                    except botocore.exceptions.ClientError as err:
                        if err.response['Error']['Code'] in ['PreconditionFailed', 'InvalidRequest']:
                            retry_count += 1
                            if retry_count >= max_retries:
                                raise Exception("Max retries exceeded")
                            continue
                        raise
                else:
                    logger.debug("Signature already exists")
                    break

            except Exception as e:
                if retry_count >= max_retries:
                    raise
                retry_count += 1
                continue

    except Exception as e:
        logger.exception("error uploading signature")
        raise