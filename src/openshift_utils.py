import logging
from kubernetes import client, config
from config import operator_logger

logger = operator_logger

class OpenShiftUtils:
    @staticmethod
    def update_bmh_status(custom_api: client.CustomObjectsApi, group: str, version: str, namespace: str, plural: str, name: str, status_update: dict) -> None:
        """Update the status of a BareMetalHost custom resource in OpenShift."""
        logger.debug(f"Updating BareMetalHost status for {name} in namespace {namespace} with {status_update}")
        try:
            custom_api.patch_namespaced_custom_object_status(
                group=group,
                version=version,
                namespace=namespace,
                plural=plural,
                name=name,
                body={"status": status_update}
            )
            logger.info(f"Successfully updated BareMetalHost status for {name}")
        except client.exceptions.ApiException as e:
            logger.error(f"Failed to update BareMetalHost status for {name}: {e}")
            raise

    @staticmethod
    def create_nmstate_config(custom_api: client.CustomObjectsApi, target_namespace: str, nmstate_config: dict, server_name: str) -> None:
        logger.debug(f"Creating NMStateConfig {server_name} in namespace {target_namespace}")
        try:
            custom_api.create_namespaced_custom_object(
                group="agent-install.openshift.io",
                version="v1beta1",
                namespace=target_namespace,
                plural="nmstateconfigs",
                body=nmstate_config
            )
            logger.info(f"Successfully created NMStateConfig nmstate-config-{server_name}")
        except client.ApiException as e:
            if e.status == 404:
                logger.error(f"NMStateConfig CRD not found in the cluster: {e}")
            elif e.status == 409:
                logger.warning(f"NMStateConfig nmstate-config-{server_name} already exists: {e}")
            else:
                logger.error(f"Failed to create NMStateConfig nmstate-config-{server_name}: {e}")
            raise

    @staticmethod
    def delete_nmstate_config(custom_api: client.CustomObjectsApi, target_namespace: str, server_name: str) -> None:
        logger.debug(f"Deleting NMStateConfig nmstate-config-{server_name} from namespace {target_namespace}")
        try:
            custom_api.delete_namespaced_custom_object(
                group="agent-install.openshift.io",
                version="v1beta1",
                namespace=target_namespace,
                plural="nmstateconfigs",
                name=f"nmstate-config-{server_name}"
                )
            logger.info(f"Successfully deleted NMStateConfig nmstate-config-{server_name}")
        except client.ApiException as e:
            if e.status == 404:
                logger.warning(f"NMStateConfig nmstate-config-{server_name} not found for deletion: {e}")
            else:
                logger.error(f"Failed to delete NMStateConfig nmstate-config-{server_name}: {e}")
            raise

    @staticmethod
    def create_bmc_secret(core_v1: client.CoreV1Api, target_namespace: str, bmc_secret: dict, server_name: str) -> None:
        logger.debug(f"Creating BMC Secret {bmc_secret['metadata']['name']} in namespace {target_namespace}")
        try:
            core_v1.create_namespaced_secret(
                namespace=target_namespace,
                body=bmc_secret
            )
            logger.info(f"Successfully created BMC Secret {bmc_secret['metadata']['name']}")
        except client.ApiException as e:
            if e.status == 409:
                logger.warning(f"BMC Secret {bmc_secret['metadata']['name']} already exists: {e}")
            else:
                logger.error(f"Failed to create BMC Secret {bmc_secret['metadata']['name']} for {server_name}: {e}")
            raise

    @staticmethod
    def delete_bmc_secret(core_v1: client.CoreV1Api, target_namespace: str, secret_name: str) -> None:
        logger.debug(f"Deleting BMC Secret {secret_name} from namespace {target_namespace}")
        try:
            core_v1.delete_namespaced_secret(
                name=secret_name,
                namespace=target_namespace
            )
            logger.info(f"Successfully deleted BMC Secret {secret_name}")
        except client.ApiException as e:
            if e.status == 404:
                logger.warning(f"BMC Secret {secret_name} not found for deletion: {e}")
            else:
                logger.error(f"Failed to delete BMC Secret {secret_name}: {e}")
            raise

    @staticmethod
    def create_baremetalhost(custom_api: client.CustomObjectsApi, target_namespace: str, bmh: dict, server_name: str) -> None:
        logger.debug(f"Creating BareMetalHost {bmh['metadata']['name']} in namespace {target_namespace}")
        try:
            custom_api.create_namespaced_custom_object(
                group="metal3.io",
                version="v1alpha1",
                namespace=target_namespace,
                plural="baremetalhosts",
                body=bmh
            )
            logger.info(f"Successfully created BareMetalHost {bmh['metadata']['name']}")
        except client.ApiException as e:
            if e.status == 409:
                logger.warning(f"BareMetalHost {bmh['metadata']['name']} already exists: {e}")
            else:
                logger.error(f"Failed to create BareMetalHost {bmh['metadata']['name']} for {server_name}: {e}")
            raise

    @staticmethod
    def delete_baremetalhost(custom_api: client.CustomObjectsApi, target_namespace: str, bmh_name: str) -> None:
        logger.debug(f"Deleting BareMetalHost {bmh_name} from namespace {target_namespace}")
        try:
            custom_api.delete_namespaced_custom_object(
                group="metal3.io",
                version="v1alpha1",
                namespace=target_namespace,
                plural="baremetalhosts",
                name=bmh_name
            )
            logger.info(f"Successfully deleted BareMetalHost {bmh_name}")
        except client.ApiException as e:
            if e.status == 404:
                logger.warning(f"BareMetalHost {bmh_name} not found for deletion: {e}")
            else:
                logger.error(f"Failed to delete BareMetalHost {bmh_name}: {e}")
            raise