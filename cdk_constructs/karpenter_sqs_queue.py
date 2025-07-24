from aws_cdk import (
    aws_sqs as sqs,
    Duration,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
)
from config.base_config import InfrastructureConfig
from constructs import Construct
from typing import List


class KarpenterSqsQueue(Construct):
    def __init__(self,
                 scope: Construct,
                 id: str,
                 cluster_name: str,
                 config: InfrastructureConfig,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.config = config
        self.cluster_name = cluster_name

        self.sqs_queue = self._create_sqs_queue()
        self.event_rules = self._create_event_rules()

    def _create_sqs_queue(self) -> sqs.Queue:
        queue = sqs.Queue(
            self, "KarpenterInterruptionQueue",
            queue_name=self.cluster_name,
            retention_period=Duration.seconds(300),
            encryption=sqs.QueueEncryption.SQS_MANAGED
        )

        # Queue Policy
        queue.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[
                    iam.ServicePrincipal("events.amazonaws.com"),
                    iam.ServicePrincipal("sqs.amazonaws.com")
                ],
                actions=["sqs:SendMessage"],
                resources=[queue.queue_arn]
            )
        )

        queue.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                actions=["sqs:*"],
                resources=[queue.queue_arn],
                conditions={"Bool": {"aws:SecureTransport": "false"}},
                principals=[iam.ArnPrincipal("*")]
            )
        )
        return queue

    def _create_event_rules(self) -> List[events.Rule]:
        rules = [
            ("ScheduledChangeRule", ["aws.health"], ["AWS Health Event"]),
            ("SpotInterruptionRule", ["aws.ec2"], ["EC2 Spot Instance Interruption Warning"]),
            ("RebalanceRule", ["aws.ec2"], ["EC2 Instance Rebalance Recommendation"]),
            ("InstanceStateChangeRule", ["aws.ec2"], ["EC2 Instance State-change Notification"]),
        ]

        for rule_name, sources, detail_types in rules:
            rule = events.Rule(
                self, rule_name,
                event_pattern=events.EventPattern(
                    source=sources,
                    detail_type=detail_types
                )
            )
            # Si FIFO, sinon supprime message_group_id
            rule.add_target(targets.SqsQueue(self.sqs_queue))

        return rules
