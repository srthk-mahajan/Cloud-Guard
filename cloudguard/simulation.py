"""Deterministic CloudGuard fixtures built on the existing one-mock CPSA account."""
import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from cpsa.cloud_sim import CloudSimulation


class CloudGuardSimulation(CloudSimulation):
    """Extend, rather than replace, CPSA's moto account and lifecycle."""

    BUCKETS = ("cloudguard-public", "cloudguard-private")
    SECURITY_GROUP = "cloudguard-open"
    ROLE = "cloudguard-instance-role"
    PROFILE = "cloudguard-instance-profile"
    DB = "cloudguard-db"
    ESCALATOR = "cloudguard-escalator"

    def __init__(self, region=None):
        super().__init__(region=region or "us-east-1")
        self.cloudguard_seeded = False
        self.secure_variant = False

    def seed_cloudguard_account(self, secure: bool = False, _retry: bool = True) -> dict:
        if self.cloudguard_seeded:
            return {"secure": self.secure_variant, "buckets": list(self.BUCKETS)}
        try:
            if not self.seeded:
                self.seed_insecure_account()
            self.secure_variant = secure
            self._seed_s3(secure)
            self._seed_iam_and_ec2(secure)
            self._seed_rds(secure)
            self.cloudguard_seeded = True
            return {"secure": secure, "buckets": list(self.BUCKETS), "db": self.DB}
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "EntityAlreadyExists" or not _retry:
                raise
            # A Streamlit rerun can be interrupted after one resource is created.
            # Restart the moto backend so the next seed cannot reuse partial state.
            self.stop()
            self.start()
            return self.seed_cloudguard_account(secure=secure, _retry=False)

    def stop(self):
        super().stop()
        self.cloudguard_seeded = False

    def _seed_s3(self, secure):
        s3 = self.client("s3")
        for bucket in self.BUCKETS:
            s3.create_bucket(Bucket=bucket)
        if secure:
            for bucket in self.BUCKETS:
                s3.put_public_access_block(
                    Bucket=bucket,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True, "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                    },
                )
                s3.put_bucket_encryption(
                    Bucket=bucket,
                    ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                )
                s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        else:
            s3.put_bucket_acl(Bucket=self.BUCKETS[0], ACL="public-read")
            s3.put_bucket_versioning(Bucket=self.BUCKETS[1], VersioningConfiguration={"Status": "Enabled"})

    def _seed_iam_and_ec2(self, secure):
        iam = self.client("iam")
        ec2 = self.client("ec2")
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=self.ROLE, AssumeRolePolicyDocument=json.dumps(trust))
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "rds:DescribeDBInstances"] if secure else "*",
                           "Resource": "arn:aws:s3:::cloudguard-private/*" if secure else "*"}],
        }
        iam.put_role_policy(RoleName=self.ROLE, PolicyName="CloudGuardRolePolicy", PolicyDocument=json.dumps(policy))
        iam.create_instance_profile(InstanceProfileName=self.PROFILE)
        iam.add_role_to_instance_profile(RoleName=self.ROLE, InstanceProfileName=self.PROFILE)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        group = ec2.create_security_group(GroupName=self.SECURITY_GROUP, Description="CloudGuard demo", VpcId=vpc)["GroupId"]
        if secure:
            ec2.authorize_security_group_ingress(
                GroupId=group, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}],
            )
        else:
            ec2.authorize_security_group_ingress(
                GroupId=group, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                                               {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            )
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1,
            InstanceType="t3.micro", SubnetId=subnet,
            SecurityGroupIds=[group], IamInstanceProfile={"Name": self.PROFILE},
        )
        if not secure:
            iam.create_user(UserName=self.ESCALATOR)
            escalation = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
            iam.put_user_policy(UserName=self.ESCALATOR, PolicyName="PassRole", PolicyDocument=json.dumps(escalation))

    def _seed_rds(self, secure):
        rds = self.client("rds")
        rds.create_db_instance(
            DBInstanceIdentifier=self.DB,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="cloudguard",
            MasterUserPassword="not-used-by-scanner",
            AllocatedStorage=20,
            PubliclyAccessible=not secure,
            StorageEncrypted=secure,
        )

    def simulate_drift(self):
        """Deliberately open SSH on the demo security group for a rescan."""
        ec2 = self.client("ec2")
        group = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [self.SECURITY_GROUP]}]
        )["SecurityGroups"][0]
        if not any(
            permission.get("FromPort") == 22
            and any(ip.get("CidrIp") == "0.0.0.0/0" for ip in permission.get("IpRanges", []))
            for permission in group.get("IpPermissions", [])
        ):
            ec2.authorize_security_group_ingress(
                GroupId=group["GroupId"],
                IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
            )
        return group["GroupId"]


def create_cloudguard_simulation(secure: bool = False) -> CloudGuardSimulation:
    sim = CloudGuardSimulation().start()
    sim.seed_cloudguard_account(secure=secure)
    return sim
