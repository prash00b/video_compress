import json
import boto3
import logging
import time
from botocore.exceptions import ClientError
import jwt
import os
import shlex

# Create S3, SSM, and Cognito clients
s3_client = boto3.client('s3', region_name='us-east-1')
ssm_client = boto3.client('ssm')
cognito_client = boto3.client('cognito-idp', region_name='us-east-1')

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

INSTANCE_ID = os.environ.get('INSTANCE_ID') 

# Function to check the state of an EC2 instance
def check_instance_state(instance_id):
    """
    Checks the current state of the specified EC2 instance.
    """
    ec2_client = boto3.client('ec2')
    try:
        response = ec2_client.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        if response['InstanceStatuses']:
            state = response['InstanceStatuses'][0]['InstanceState']['Name']
            return state
        else:
            logger.error(f"No instance found with ID: {instance_id}")
            return None
    except ClientError as e:
        logger.error(f"Error checking instance state: {str(e)}")
        return None

# Function to send an SSM command to execute a shell script on an EC2 instance
def send_ssm_command(bucket_name, object_key, user_id, content_type):
    """
    Sends an SSM command to the specified EC2 instance to execute a video compression script.
    """
    try:
        instance_state = check_instance_state(INSTANCE_ID)
        if instance_state != 'running':
            logger.error(f"Instance {INSTANCE_ID} is not running. Current state: {instance_state}")
            return None, f"Instance is not running. Current state: {instance_state}"

        # Escape inputs to prevent shell command injection
        escaped_bucket_name = shlex.quote(bucket_name)
        escaped_object_key = shlex.quote(object_key)
        escaped_user_id = shlex.quote(user_id)
        escaped_content_type = shlex.quote(content_type) if content_type else shlex.quote("None")
        logger.info(f"Escaped content type: {escaped_content_type}")

        # Send the SSM command
        ssm_response = ssm_client.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName="AWS-RunShellScript",
            
            Parameters={
                "commands": [
                    "source /home/ec2-user/my_env/bin/activate",
                    f"python3 /home/ec2-user/compression_function.py {escaped_bucket_name} {escaped_object_key} {escaped_user_id} {escaped_content_type}"
                ]
            }
        )
        command_id = ssm_response['Command']['CommandId']
        logger.info(f"SSM command sent for {object_key} with command ID: {command_id}")
        return command_id, None
    except Exception as e:
        logger.error(f"An error occurred for {object_key}: {str(e)}")
        return None, str(e)

# Function to delete an object from an S3 bucket
def delete_s3_object(bucket_name, object_key):
    """
    Deletes an object from the specified S3 bucket.
    """
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=object_key)
        logger.info(f"Deleted S3 object '{object_key}' from bucket '{bucket_name}'.")
    except ClientError as e:
        logger.error(f"Failed to delete S3 object '{object_key}': {e.response['Error']['Message']}")

# Function to wait for the result of an SSM command
def wait_for_command_result(command_id, timeout=200):
    """
    Waits for the result of the SSM command execution.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        time.sleep(10)
        try:
            ssm_response = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=INSTANCE_ID
            )
            command_status = ssm_response['Status']
            
            logger.info(f"Raw SSM response: {ssm_response}")
            logger.info(f"Command output: {ssm_response.get('StandardOutputContent', 'No output content')}")
            if ssm_response.get('StandardErrorContent'):
                logger.error(f"Command error: {ssm_response.get('StandardErrorContent')}")
            
            if command_status in ['Success', 'Failed', 'TimedOut', 'Cancelled']:
                logger.info(f"Final command status: {command_status}")
                
                try:
                    output_content = json.loads(ssm_response.get('StandardOutputContent', '{}'))
                except json.JSONDecodeError:
                    logger.error("Failed to parse command output as JSON")
                    output_content = {'statusCode': 500, 'body': 'Failed to parse command output'}                

                return {
                    'Status': command_status,
                    'OutputContent': output_content
                }

            else:
                logger.info(f"Command status: {command_status}. Waiting for completion...")
        except ClientError as e:
            logger.error(f"Error getting command invocation: {str(e)}")
            return None

    logger.error(f"Command timed out after {timeout} seconds")
    return None

# Lambda function handler
def lambda_handler(event, context):
    """
    Main Lambda handler for processing video upload requests.
    Validates inputs, checks S3 object, sends SSM commands, and processes results.
    """
    logger.info("Lambda function started execution.")
    logger.info(f"Event: {json.dumps(event)}")
    
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Credentials': 'false',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    }
        
    try:
        # Authorization token processing
        auth_header = event.get('headers', {}).get('access_token')
        
        if not auth_header:
            logger.error("Unauthorized: Missing access token")
            return {'statusCode': 401, 'body': json.dumps({'message': 'Unauthorized: Missing access token'}), 'headers': headers}

        try:
            token_type, token = auth_header.split()
        except ValueError:
            logger.error("Invalid token: Token format incorrect")
            return {'statusCode': 401, 'body': json.dumps({'message': 'Invalid token: Token format incorrect'}), 'headers': headers}
        
        if token_type.lower() != 'bearer':
            logger.error("Invalid authorization type: Authorization type is not Bearer")
            return {'statusCode': 401, 'body': json.dumps({'message': 'Invalid authorization type: Authorization type is not Bearer'}), 'headers': headers}

        # Validate token with Cognito
        user_info = cognito_client.get_user(AccessToken=token)
        user_attributes = user_info['UserAttributes']
        user_id = next(attr['Value'] for attr in user_attributes if attr['Name'] == 'sub')
        
        # Parse request body
        body = json.loads(event['body'])
        object_path = body.get('path')
        bucket_name = body.get('bucket')
        content_type = body.get('content-type', 'application/octet-stream')

        # Check if S3 object exists
        s3_client.head_object(Bucket=bucket_name, Key=object_path)
        
        # Send SSM command and wait for result
        command_id, error_message = send_ssm_command(bucket_name, object_path, user_id, content_type)
        if error_message:
            return {'statusCode': 500, 'body': json.dumps({'message': error_message}), 'headers': headers}

        command_result = wait_for_command_result(command_id)
        # Process result...

    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}", exc_info=True)
        return {'statusCode': 500, 'body': json.dumps({'message': str(e)}), 'headers': headers}
    finally:
        if 'object_path' in locals() and 'bucket_name' in locals():
            delete_s3_object(bucket_name, object_path)
