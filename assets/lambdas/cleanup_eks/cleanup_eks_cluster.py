import json
import boto3
import subprocess
import os
import logging
import cfnresponse
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    """Lambda handler to launch CodeBuild for cleanup and delete ENIs on stack deletion."""

    try:
        logger.info("📦 Event received:\n%s", json.dumps(event, indent=2))
        # Only execute cleanup on DELETE event
        if event.get('RequestType') != 'Delete':
            logger.info("Not a DELETE event, skipping cleanup")
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {
                'Message': 'Cleanup skipped - not a DELETE event'
            })
            return

        cluster_name = os.environ.get('CLUSTER_NAME')
        region = os.environ.get('EKS_REGION')
        codebuild_project = os.environ.get('CODEBUILD_PROJECT_NAME')

        logger.info(f"Starting cleanup for cluster: {cluster_name} using CodeBuild project: {codebuild_project}")

        codebuild = boto3.client('codebuild', region_name=region)
        ec2 = boto3.client('ec2', region_name=region)

        # Start CodeBuild job
        build_response = codebuild.start_build(projectName=codebuild_project)
        build_id = build_response['build']['id']
        logger.info(f"Started CodeBuild build: {build_id}")

        # Wait for CodeBuild job to complete (timeout: 10 minutes)
        timeout_seconds = 600
        poll_interval = 10
        elapsed = 0
        build_status = None
        eni_ids_before = get_all_eni_ids(ec2)

        while elapsed < timeout_seconds:
            build_info = codebuild.batch_get_builds(ids=[build_id])['builds'][0]
            build_status = build_info['buildStatus']
            if build_status in ['SUCCEEDED', 'FAILED', 'FAULT', 'STOPPED', 'TIMED_OUT']:
                logger.info(f"CodeBuild build finished with status: {build_status}")
                break
            time.sleep(poll_interval)
            elapsed += poll_interval
        else:
            logger.warning("CodeBuild build did not finish within timeout.")

        # Identify and delete ENIs created by CodeBuild job
        eni_ids_after = get_all_eni_ids(ec2)
        new_enis = list(set(eni_ids_after) - set(eni_ids_before))
        logger.info(f"ENIs to delete: {new_enis}")
        for eni_id in new_enis:
            try:
                # Detach if attached
                eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])['NetworkInterfaces'][0]
                if eni.get('Attachment'):
                    ec2.detach_network_interface(AttachmentId=eni['Attachment']['AttachmentId'], Force=True)
                    logger.info(f"Detached ENI: {eni_id}")
                # Delete ENI
                ec2.delete_network_interface(NetworkInterfaceId=eni_id)
                logger.info(f"Deleted ENI: {eni_id}")
            except Exception as e:
                logger.warning(f"Failed to delete ENI {eni_id}: {str(e)}")

        cfnresponse.send(event, context, cfnresponse.SUCCESS, {
            'Message': f'Cleanup CodeBuild build status: {build_status}. ENIs deleted: {new_enis}'
        })

    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {
            'Message': 'Cleanup failed'
        })
        raise e


def get_all_eni_ids(ec2_client):
    """Helper to get all ENI IDs in the region."""
    eni_ids = []
    paginator = ec2_client.get_paginator('describe_network_interfaces')
    for page in paginator.paginate():
        for eni in page['NetworkInterfaces']:
            eni_ids.append(eni['NetworkInterfaceId'])
    return eni_ids
