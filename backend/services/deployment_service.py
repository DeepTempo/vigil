class DeploymentService:
    """
    Service for deploying detection rules to production SIEMs.
    Current implementation is gated for security until a formal 
    human-in-the-loop approval workflow is implemented.
    """

    def request_approval(self, rule: dict) -> bool:
        """
        Gated: Always returns False until workflow is implemented.
        """
        # TODO: Integrate with Vigil Case Management for human approval
        return False

    def deploy(self, rule: dict, target: str):
        """
        Gated: Raises error to prevent accidental unapproved deployments.
        """
        raise NotImplementedError(
            "Direct deployment is disabled. Rules must be approved via Case Management."
        )
