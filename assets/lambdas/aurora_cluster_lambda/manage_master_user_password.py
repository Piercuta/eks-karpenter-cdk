import boto3
import json
import cfnresponse
import time


def handler(event, context):
    if event['RequestType'] in ['Create', 'Update']:
        try:
            rds_client = boto3.client('rds')

            # Get parameters
            cluster_id = event['ResourceProperties']['ClusterId']
            kms_key_id = event['ResourceProperties']['KmsKeyId']

            # Enable manage_master_user_password
            rds_client.modify_db_cluster(
                DBClusterIdentifier=cluster_id,
                ManageMasterUserPassword=True,
                MasterUserSecretKmsKeyId=kms_key_id,
                ApplyImmediately=True
            )

            # Wait for the modification to be applied
            print(f"Waiting for cluster {cluster_id} to be modified...")
            waiter = rds_client.get_waiter('db_cluster_available')
            waiter.wait(
                DBClusterIdentifier=cluster_id,
                WaiterConfig={
                    'Delay': 30,
                    'MaxAttempts': 20
                }
            )

            print(f"Successfully enabled manage_master_user_password for cluster {cluster_id}")
            response = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)
            secret_arn = response['DBClusters'][0].get('MasterUserSecret', {}).get('SecretArn')

            cfnresponse.send(event, context, cfnresponse.SUCCESS, {
                'SecretArn': secret_arn
            })
        except Exception as e:
            print(f"Error: {str(e)}")
            cfnresponse.send(event, context, cfnresponse.FAILED, {'SecretArn': ''})
    else:
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {'SecretArn': ''})
