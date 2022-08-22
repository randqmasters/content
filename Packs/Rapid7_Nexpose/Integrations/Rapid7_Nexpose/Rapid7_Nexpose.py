import re
import urllib3

import demistomock as demisto

from enum import Enum
from time import strptime, struct_time

from CommonServerPython import *
from CommonServerUserPython import *

API_DEFAULT_PAGE_SIZE = 10  # Default page size that's set on the API. Used for calculations.
DEFAULT_PAGE_SIZE = 50  # Default page size to use
MATCH_DEFAULT_VALUE = "any"  # Default "match" value to use when using search filters. Can be either "all" or "any".
REPORT_DOWNLOAD_WAIT_TIME = 60  # Time in seconds to wait before downloading a report after starting its generation

urllib3.disable_warnings()  # Disable insecure warnings


# TODO:
# 1. Change command return types from dict to CommandResults
# 2. Raise error if non valid HTTP status code is returned.


class SiteImportance(Enum):
    """An Enum with possible site importance values."""
    VERY_LOW = 1
    LOW = 2
    NORMAL = 3
    HIGH = 4
    VERY_HIGH = 5


class ScanStatus(Enum):
    """An Enum with scan status values."""
    PAUSE = 1
    RESUME = 2
    STOP = 3


class InvalidSiteNameException(DemistoException):
    pass


class Client(BaseClient):
    """Client class for interactions with Rapid7 Nexpose API."""

    def __init__(self, url: str, username: str, password: str, token: Union[str, None] = None, verify: bool = True):
        """
        Initialize the client.

        Args:
            url (str): Nexpose server base URL.
            username (str): Username to use for authentication.
            password (str): Password to use for authentication.
            token (str | None, optional): 2FA token to use for authentication.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """

        self._headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Add 2FA token to headers if provided
        if token:
            self._headers.update({"Token": token})

        super().__init__(
            base_url=url.rstrip("/") + "/api/3",
            auth=(username, password),
            headers=self._headers,
            verify=verify,
        )

    def _paged_http_request(self, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                            sort: Union[str, None] = None, limit: Union[int, None] = None, **kwargs) -> list:
        """
        Run _http_request with pagination handling.

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of items to return. None means to not use a limit.
                Defaults to None.
            **kwargs: Parameters to pass when calling `_http_request`.

        Returns:
            list: A list containing all paginated items.
        """
        kwargs["params"] = kwargs.get("params", {})  # If `params` is None, set it to an empty dict

        # If sort is not None, split it into a list
        if sort:
            sort = sort.split(sep=";")

        kwargs["params"].update(find_valid_params(
            page_size=page_size,
            sort=sort,
            limit=limit,
        ))

        response: dict = self._http_request(**kwargs)
        result = response.get("resources", [])

        if not result:
            return []

        # If page_size is set to None, the size that will be used is API's default
        _page_size = page_size if page_size else API_DEFAULT_PAGE_SIZE

        page_count = 1

        while page_count < response["page"]["totalPages"] and (limit is None or ((page_count * _page_size) < limit)):
            page_count += 1
            kwargs["params"]["page"] = str(page_count)
            response = self._http_request(**kwargs)
            result.extend(response.get("resources"))

        if limit and limit < len(result):
            return result[:limit]

        return result

    def create_report(self, report_id: str) -> dict:
        """
        | Generates a configured report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/generateReport

        Args:
            report_id (str): ID of the configured report to generate.

        Returns:
            dict: API response with information about the generated report.
        """
        return self._http_request(
            url_suffix=f"/reports/{report_id}/generate",
            method="POST",
            resp_type="json",
        )

    def create_report_config(self, scope: dict[str, Any], template_id: str,
                             report_name: str, report_format: str) -> dict:
        """
        | Create a new report configuration.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createReport

        Args:
            scope (dict[str, Any]): Scope of the report, see Nexpose's documentation for more details.
            template_id (str): ID of report template to use.  # TODO: should be optional?
            report_name (str): Name for the report that will be generated.
            report_format (str): Format of the report that will be generated.  # TODO: Add a list of available formats to use.

        Returns:
            dict: API response with information about the generated report configuration.
        """

        if not template_id:
            templates = self.get_report_templates()

            if not templates.get("resources"):
                return "No templates found"  # TODO: Remove this return statement

            template_id = templates["resources"][0][
                "id"]  # TODO: Move to `_command` function (instead of in client method)

        post_data = {
            "scope": scope,
            "template": template_id,
            "name": report_name,
            "format": report_format
        }

        return self._http_request(
            url_suffix=f"/reports",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def create_site(self, name: str, description: Union[str, None] = None, assets: Union[list[str], None] = None,
                    site_importance: Union[str, None] = None, template_id: Union[str, None] = None) -> dict:
        """
        | Create a new site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSite

        Args:
            name (str): Name of the site. Must be unique.
            description (str | None, optional): Description of the site. Defaults to None.
            assets (list[str] | None, optional): List of asset IDs to be included in site scans. Defaults to None.
            site_importance (str | None, optional): Importance of the site. Can be either:
                "very_low", "low", "normal", "high" or "very_high".
                Defaults to None (results in using API's default - "normal").
            template_id (str | None, optional): The identifier of a scan template.
                Defaults to None (results in using default scan template).

        Returns:
            dict: API response with information about the newly created site.
        """
        post_data = find_valid_params(
            name=name,
            description=description,
            importance=site_importance,
            template_id=template_id,
            scanTemplateId=template_id,
        )

        if assets:
            post_data["scan"] = {
                "assets": {
                    "includedTargets": {
                        "addresses": assets
                    }}}

        return self._http_request(
            url_suffix=f"/sites",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def delete_site(self, site_id: str) -> dict:
        """
        | Delete a site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/deleteSite

        Args:
            site_id (str): ID of the site to delete.

        Returns:
            dict: API response with information about the deleted site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}",
            method="DELETE",
            resp_type="json",
        )

    def download_report(self, report_id: str, instance_id: str) -> bytes:
        """
        | Download a report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/generateReport

        Args:
            report_id (str): ID of the report to download.
            instance_id (str): ID of the report instance.

        Returns:
            bytes: Report file in bytes.
        """
        headers = {  # TODO: Check if should be removed (why application/json if bytes are returned?)
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br"
        }

        return self._http_request(
            url_suffix=f"reports/{report_id}/history/{instance_id}/output",
            headers=headers,
            method="GET",
            resp_type="content",
        )

    def get_asset_vulnerability(self, asset_id: str, vulnerability_id: str) -> dict:
        """
        | Retrieve information about vulnerability findings on an asset.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerability

        Args:
            asset_id (str): ID of the asset to retrieve information about.
            vulnerability_id (str): ID of the vulnerability to look for.

        Returns:
            dict: API response with information about vulnerability findings on the asset.
        """
        return self._http_request(
            url_suffix=f"assets/{asset_id}/vulnerabilities/{vulnerability_id}",
            method="GET",
            resp_type="json",
        )

    def get_asset_vulnerabilities(self, asset_id: str, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                                  sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieves a list of all vulnerability findings on an asset.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerabilities

        Args:
            asset_id (str): ID of the site to retrieve linked assets from.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of assets to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list with all vulnerability findings on an asset.
        """
        return self._paged_http_request(
            url_suffix=f"/assets/{asset_id}/vulnerabilities",
            method="GET",
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_asset(self, asset_id: str) -> dict:
        """
        | Retrieve information about a specific asset.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAsset

        Args:
            asset_id (str): ID of the asset to retrieve information about.

        Returns:
            dict: API response with information about a specific asset.
        """
        return self._http_request(
            url_suffix=f"/assets/{asset_id}",
            method="GET",
            resp_type="json",
        )

    def get_assets(self, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                   sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve a list of all assets.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssets

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of assets to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of all assets (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix="/assets",
            method="GET",
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_assigned_shared_credentials(self, site_id: str) -> dict:
        """
        | Retrieve information about all credentials that are shared with a specific site.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteSharedCredentials

        Args:
            site_id (str): ID of the site to retrieve credentials that are shared with.

        Returns:
            dict: API response with information shared credentials that are shared with a specific site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/shared_credentials",
            method="GET",
            resp_type="json",
        )

    def get_report_history(self, report_id: str, instance_id: str) -> dict:
        """
        | Retrieve information about a generated report.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getReportInstance

        Args:
            report_id (str): ID of the report to retrieve information about.
            instance_id (str): ID of the report instance to retrieve information about.

        Returns:
            dict: API response with information about the generated report.
        """
        return self._http_request(
            url_suffix=f"/reports/{report_id}/history/{instance_id}",
            method="GET",
            resp_type="json",
        )

    def get_report_templates(self) -> dict:
        """
        | Retrieve a list of all available report templates.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getReportTemplates

        Returns:
            dict: API response with information about all available report templates.
        """
        return self._http_request(
            url_suffix="/report_templates",
            method="GET",
            resp_type="json",
        )

    def get_scan(self, scan_id: str) -> dict:
        """
        | Retrieve information about a specific scan.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getScan

        Args:
            scan_id (str): ID of the scan to retrieve.

        Returns:
            dict: API response with information about a specific scan.
        """
        return self._http_request(
            url_suffix=f"/scan/{scan_id}",
            method="GET",
            resp_type="json",
        )

    def get_scans(self, active: Union[bool, None] = False, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                  sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve a list of all scans.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getScans

        Args:
            active (bool | None, optional): Whether to return active scans or not. Defaults to False.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of all scans (up to a limit, if set).
        """
        params = {"active": active}

        return self._paged_http_request(
            url_suffix="/scans",
            method="GET",
            params=params,
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_scan_schedule(self, site_id: str, schedule_id: str) -> dict:
        """
        | Retrieve information about a specific scheduled scan from a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedule

        Args:
            site_id (str): ID of the site to retrieve scheduled scan from.
            schedule_id (str): ID of the scheduled scan to retrieve.

        Returns:
            dict: API response with information about a specific scheduled scans from the specific site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules/{schedule_id}",
            method="GET",
            resp_type="json",
        )

    def get_scan_schedules(self, site_id: str) -> dict:
        """
        | Retrieve information about all scheduled scans from a specific site.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScanSchedules

        Args:
            site_id (str): ID of the site to retrieve scheduled scans from.

        Returns:
            dict: API response with information about all scheduled scans from the specific site.
        """
        return self._http_request(
            url_suffix=f"/sites/{site_id}/scan_schedules",
            method="GET",
            resp_type="json",
        )

    def get_shared_credential(self, credential_id: str) -> dict:
        """
        | Retrieve information about a specific shared credential.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSharedCredential

        Args:
            credential_id (str): ID of the shared credential to retrieve information about.

        Returns:
            dict: API response with information about a specific shared credential.
        """
        return self._http_request(
            url_suffix=f"/shared_credentials/{credential_id}",
            method="GET",
            resp_type="json",
        )

    def get_shared_credentials(self) -> dict:
        """
        | Retrieve information about all shared credentials.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSharedCredentials

        Returns:
            dict: API response with all shared credentials and their information.
        """
        return self._http_request(
            url_suffix=f"/shared_credentials",
            method="GET",
            resp_type="json",
        )

    def get_site_assets(self, site_id: str, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                        sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve a list of all assets that are linked with a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteAssets

        Args:
            site_id (str): ID of the site to retrieve linked assets from.
            page_size (int | None, optional): Number of assets to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list with all assets that are linked with a specific site (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix=f"/sites/{site_id}/assets",
            method="GET",
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_site_scans(self, site_id: str, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                       sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve a list of scans from a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteScans

        Args:
            site_id (str): ID of the site to retrieve scans from.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: API response with information about all scans from the specific site.
        """
        return self._paged_http_request(
            url_suffix=f"/sites/{site_id}/scans",
            method="GET",
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_sites(self, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                  sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve a list of sites.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSites

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of sites (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix="/sites",
            method="GET",
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_vulnerabilities(self, page_size: Union[int, None] = DEFAULT_PAGE_SIZE,
                            sort: Union[str, None] = None, limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve information about all existing vulnerabilities.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilities

        Args:
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of sites (up to a limit, if set).
        """
        return self._paged_http_request(
            url_suffix="/vulnerabilities",
            method="GET",
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def get_vulnerability(self, vulnerability_id: str) -> dict:
        """
        | Retrieve information about a specific vulnerability.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerability

        Args:
            vulnerability_id (str): ID of the vulnerability to retrieve information about.

        Returns:
            dict: API response with information about a specific vulnerability.
        """
        return self._http_request(
            url_suffix=f"/vulnerabilities/{vulnerability_id}",
            method="GET",
            resp_type="json",
        )

    def get_vulnerability_exception(self, vulnerability_exception_id: str) -> dict:
        """
        | Retrieve information about an exception made on a vulnerability.
        |
        | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilityException

        Args:
            vulnerability_exception_id (str): ID of the vulnerability exception to retrieve information about.

        Returns:
            dict: API response with information about a specific exception made on a vulnerability.
        """
        return self._http_request(
            url_suffix=f"/vulnerabilities/{vulnerability_exception_id}",
            method="GET",
            resp_type="json",
        )

    def get_asset_vulnerability_solution(self, asset_id: str, vulnerability_id: str) -> dict:
        """
        | Retrieve information about solutions that can be used to remediate a vulnerability on an asset.
        |
        | | For more information see:
            https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerabilitySolutions

        Args:
            asset_id (str): ID of the asset to retrieve solutions for.
            vulnerability_id (str): ID of the vulnerability to retrieve solutions for.

        Returns:
            dict: API response with information about solutions that can be used to remediate
                a vulnerability on an asset.
        """
        return self._http_request(
            url_suffix=f"/assets/{asset_id}/vulnerabilities/{vulnerability_id}/solution",
            method="GET",
            resp_type="json",
        )

    def search_assets(self, filters: Union[list[dict], None], match: str = MATCH_DEFAULT_VALUE,
                      page_size: Union[int, None] = DEFAULT_PAGE_SIZE, sort: Union[str, None] = None,
                      limit: Union[int, None] = None) -> list[dict]:
        """
        | Retrieve a list of all assets with access permissions that match the provided search filters.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/findAssets

        Args:
            filters (list[dict] | None, optional): List of filters to use for searching assets. Defaults to None.
            match (str, optional): Determine if the filters should match all or any of the filters.
                Can be either "all" or "any". Defaults to MATCH_DEFAULT_VALUE.
            page_size (int | None, optional): Number of scans to return per page when using pagination.
                Defaults to DEFAULT_PAGE_SIZE.
            sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format.
                Defaults to None.
            limit (int | None, optional): Limit the number of sites to return. None means to not use a limit.
                Defaults to None.

        Returns:
            list[dict]: A list of assets (up to a limit, if set) matching the filters.
        """
        post_data = find_valid_params(
            filters=filters,
            match=match,
        )

        return self._paged_http_request(
            url_suffix="/assets/search",
            method="POST",
            json_data=post_data,
            page_size=page_size,
            sort=sort,
            limit=limit,
            resp_type="json",
        )

    def start_site_scan(self, site_id: str, scan_name: str, hosts: list[str]) -> dict:
        """
        | Start a scan for a specific site.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/startScan

        Args:
            site_id (str): ID of the site to start a scan on.
            scan_name (str): Name to set for the new scan.
            hosts (list[str]): Hosts to scan.

        Returns:
            dict: API response with information about the started scan.
        """
        post_data = {
            "name": scan_name,
            "hosts": hosts
        }

        return self._http_request(
            url_suffix=f"/sites/{site_id}/scans",
            method="POST",
            json_data=post_data,
            resp_type="json",
        )

    def update_scan_status(self, scan_id: str, status: str) -> dict:
        """
        | Update status for a specific scan.
        |
        | For more information see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/setScanStatus

        Args:
            scan_id (str): ID of the scan to update.
            status (str): Status to set the scan to. Can be either "pause", "stop", or "resume".
        """
        return self._http_request(
            url_suffix=f"/scans/{scan_id}/{status}",
            method="POST",
            resp_type="json",
        )

    def find_site_id(self, name: str) -> Union[str, None]:
        """
        Find a site ID by its name.

        Returns:
            str | None: Site ID corresponding to the passed name. None if no match was found.
        """
        response = self._http_request(
            url_suffix=f"/sites",
            method="GET",
            resp_type="json",
        )

        for item in response.get(
                "resources"):  # TODO: Check how response looks when there are no sites, and adjust accordingly
            if item["name"] == name:
                return item["id"]

        return None


class Site:
    """A class representing a site, which can be identified by ID or name."""

    def __init__(self, site_id: Union[str, None] = None,
                 site_name: Union[str, None] = None, client: Union[Client, None] = None) -> None:
        """
        Create a new Site object.
        Required parameters are either `site_id`, or both `site_name` and `client`.

        Args:
            site_id (str | None, optional): ID of the site.
            site_name (str | None, optional): Name of the site to create an object for.
            client (Client | None): Client object to use for API requests.
                Required to fetch ID if only name is provided.

        Raises:
            ValueError: If neither of `site_id` and `site_name` was provided,
            or `site_name` was provided without a `site_id`, and `client` was not provided.
            InvalidSiteNameException: If no ID was provided and a site with a matching name could not be found.
        """
        if site_id:
            self.id = site_id

        elif site_name:
            if not client:
                raise ValueError("Can't fetch site ID as no Client was provided.")

            self.id = client.find_site_id(site_name)

            if not self.id:
                raise InvalidSiteNameException(f"No site with name `{site_name}` was found.")

        else:
            raise ValueError("Site must have either an ID or a name.")

        self.name = site_name
        self._client = client


def get_session():
    # TODO: Remove alongside get_site once get_site is removed
    url = demisto.params()["url"].rstrip("/") + "/data/user/login"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    if demisto.params().get("token"):
        headers["token"] = demisto.params().get("token")

    body = {
        "nexposeccusername": demisto.params()["credentials"]["identifier"],
        "nexposeccpassword": demisto.params()["credentials"]["password"]
    }

    res = requests.post(url, headers=headers, data=body, verify=not demisto.params().get("unsecure", False))
    if res.status_code < 200 or res.status_code >= 300:
        return ""
    body = res.json()
    if "sessionID" not in body:
        return ""

    return body["sessionID"]


def get_site(asset_id: str):
    # TODO: Remove demisto.params() and improve code
    # TODO: Check why this function uses a non-API endpoint, and adjust this function accordingly.
    url = demisto.params()["url"].rstrip("/") + "/data/assets/" + str(asset_id) + "/scans"
    username = demisto.params()["credentials"]["identifier"]
    password = demisto.params()["credentials"]["password"]
    token = demisto.params().get("token")
    verify = not demisto.params().get("unsecure", False)
    session = get_session()

    headers = {"Content-Type": "application/json"}

    if token:
        headers["token"] = token

    headers["Cookie"] = "nexposeCCSessionID=" + session
    headers["nexposeCCSessionID"] = session

    res = requests.post(url, headers=headers, auth=(username, password), verify=verify)

    if res.status_code < 200 or res.status_code >= 300:
        return ""

    response = res.json()
    if response is None or response["records"] is None or len(response["records"]) == 0:
        return ""

    return {
        "id": response["records"][0]["siteID"],
        "name": response["records"][0]["siteName"],
        "ip": response["records"][0]["ipAddress"]
    }


def iso8601_duration_as_minutes(duration):
    # TODO
    year_in_minutes = 525600
    month_in_minutes = 43800
    week_in_minutes = 10080
    day_in_minutes = 1440
    hour_in_minutes = 60

    if duration is None:
        return 0
    if duration[0] != "P":
        raise ValueError("Not an ISO 8601 Duration string")
    minutes = 0
    # split by the "T"
    for i, item in enumerate(duration.split("T")):
        for number, period in re.findall("(?P<number>\d+)(?P<period>S|M|H|D|W|Y)", item):
            # print "%s -> %s %s" % (d, number, unit)
            number = float(number)
            this = 0
            if period == "Y":
                this = number * year_in_minutes  # 365.25
            elif period == "W":
                this = number * week_in_minutes
            elif period == "D":
                this = number * day_in_minutes
            elif period == "H":
                this = number * hour_in_minutes
            elif period == "M":
                # ambiguity between months and minutes
                if i == 0:
                    this = number * month_in_minutes  # assume 30 days
                else:
                    this = number
            elif period == "S":
                this = number / 60
            minutes = minutes + this
    return minutes


def replace_key_names(data: Union[dict, list, tuple, set], name_mapping: dict, recursive: bool = False):
    """
    Replace key names in a dictionary.

    Args:
        data (dict | list | tuple | set): An iterable to replace key names for dictionaries within it.
        name_mapping (dict): A dictionary in a `from: to` mapping format of which key names to replace with what.
        recursive (bool, optional): Whether to replace key names in all sub-dictionaries. Defaults to False.

    Returns:
        dict: The (same) dictionary with its key names replaced according to mapping.
    """
    for item in data:
        if isinstance(data, dict) and item in name_mapping:
            # If the new key already exists
            if name_mapping[item] in data:
                raise ValueError(f"Key name conflict: Key '{name_mapping[item]}' already exists.")

            data[name_mapping[item]] = data.pop(item)

        if recursive and isinstance(data[item], dict):
            data[item] = replace_key_names(data[item], name_mapping, recursive)

    return data


def find_asset_last_change(asset_data: dict) -> dict:
    """
    Retrieve the last change (usually a scan) from an asset's history.

    Args:
        asset_data (dict): The asset data as it was retrieved from the API.

    Returns:
        dict: A dictionary containing data about the latest change in asset's history.
    """
    if not asset_data.get("history"):
        return {
            "date": "-",
            "id": "-"
        }

    sorted_scans = sorted(asset_data["history"], key=lambda x: convert_datetime_str(x.get("date")), reverse=True)

    return {
        "date": sorted_scans[0]["date"] if "date" in sorted_scans[0] else "-",
        "id": sorted_scans[0]["scanId"] if "scanId" in sorted_scans[0] else "-"
    }


def convert_datetime_str(time_str: str) -> struct_time:
    """
    Convert a time string formatted in one of the time formats used by Nexpose's API for scans to a `struct_time` object.

    Args:
        time_str (str): A time string formatted in one of the time formats used by Nexpose's API for scans.

    Returns:
        struct_time: The datetime represented in a `struct_time` object.
    """
    try:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")

    except ValueError:
        return strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")


def dq(obj, path):
    """
    return a value in an object path. in case of multiple objects in path, searches them all.
    @param obj - dictionary tree to search in
    @param path (list) - a path of the desired value in the object. for example ['root', 'key', 'subkey']
    """
    # TODO: Remove or rewrite this function
    if len(path) == 0:
        return obj

    if isinstance(obj, dict):
        if path[0] in obj:
            return dq(obj[path[0]], path[1:])
    elif isinstance(obj, list):
        # in case current obj has multiple objects, search them all.
        line = [dq(o, path) for o in obj]
        return [k for k in line if k is not None]

    # in case of error in the path
    return None


def get_asset_command(client: Client, asset_id: str):
    """
    Retrieve information about an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
    """
    asset = client.get_asset(asset_id)

    if asset.get("status") == "404":
        return "Asset not found"

    last_scan = find_asset_last_change(asset)
    asset["LastScanDate"] = last_scan["date"]
    asset["LastScanId"] = last_scan["id"]
    asset["Site"] = get_site(asset["id"])["name"]

    asset_headers = [
        "AssetId",
        "Addresses",
        "Hardware",
        "Aliases",
        "HostType",
        "Site",
        "OperatingSystem",
        "CPE",
        "LastScanDate",
        "LastScanId",
        "RiskScore"
    ]

    asset_output = replace_key_names(
        data=asset,
        name_mapping={
            "id": "AssetId",
            "addresses.ip": "Addresses",
            "addresses.mac": "Hardware",
            "hostNames.name": "Aliases",
            "type": "HostType",
            "Site": "Site",
            "os": "OperatingSystem",
            "vulnerabilities.total": "Vulnerabilities",
            "cpe.v2.3": "CPE",
            "LastScanDate": "LastScanDate",
            "LastScanId": "LastScanId",
            "riskScore": "RiskScore",
        },
        recursive=True,  # TODO: Check if should be False
    )

    software_headers = None
    software_output = None
    service_headers = None
    services_output = None
    users_headers = None
    users_output = None

    if "software" in asset and len(asset["software"]) > 0:  # TODO: Replace with: if len(asset.get("software", [])) > 0
        software_headers = [
            "Software",
            "Version",
        ]

        software_output = replace_key_names(
            data=asset["software"],
            name_mapping={
                "description": "Software",
                "version": "Version",
            },
            recursive=True,  # TODO: Check if should be False
        )

    if "services" in asset and len(asset["services"]) > 0:
        service_headers = [
            "Name",
            "Port",
            "Product",
            "Protocol",
        ]

        services_output = replace_key_names(
            data=asset["services"],
            name_mapping={
                "name": "Name",
                "port": "Port",
                "product": "Product",
                "protocol": "Protocol",
            },
            recursive=True,  # TODO: Check if should be False
        )

    if "users" in asset and len(asset["users"]) > 0:
        users_headers = [
            "FullName",
            "Name",
            "UserId",
        ]

        users_output = replace_key_names(
            data=asset["users"],
            name_mapping={
                "name": "Name",
                "fullName": "FullName",
                "id": "UserId",
            },
            recursive=True,  # TODO: Check if should be False
        )

    vulnerability_headers = [
        "Id",
        "Title",
        "Malware",
        "Exploit",
        "CVSS",
        "Risk",
        "PublishedOn",
        "ModifiedOn",
        "Severity",
        "Instances",
    ]

    vulnerabilities = client.get_vulnerabilities(asset["id"])
    asset["vulnerabilities"] = vulnerabilities

    vulnerabilities_output = []
    cves_output = []

    for idx, vulnerability in enumerate(asset["vulnerabilities"]):
        extra_info = client.get_vulnerability(vulnerability["id"])
        asset["vulnerabilities"][idx].update(extra_info)

        cvss = dq(extra_info["cvss"], ["v2", "score"])  # TODO: Find a more intuitive way to do this without dq

        if "cves" in extra_info:
            cves_output.extend(
                [{"ID": cve} for cve in extra_info["cves"]]
            )

        output_vuln = {
            "Id": vulnerability["id"],
            "Title": extra_info["title"],
            "Malware": extra_info["malwareKits"],
            "Exploit": extra_info["exploits"],
            "CVSS": cvss,
            "Risk": extra_info["riskScore"],
            "PublishedOn": extra_info["published"],
            "ModifiedOn": extra_info["modified"],
            "Severity": extra_info["severity"],
            "Instances": vulnerability["instances"],
        }

        vulnerabilities_output.append(output_vuln)

    asset_md = tableToMarkdown("Nexpose asset " + str(asset["id"]), asset_output, asset_headers, removeNull=True)
    vulnerabilities_md = tableToMarkdown("Vulnerabilities", vulnerabilities_output, vulnerability_headers,
                                         removeNull=True) if len(vulnerabilities_output) > 0 else ""
    software_md = tableToMarkdown("Software", software_output, software_headers,
                                  removeNull=True) if software_output is not None else ""
    services_md = tableToMarkdown("Services", services_output, service_headers,
                                  removeNull=True) if services_output is not None else ""
    users_md = tableToMarkdown("Users", users_output, users_headers,
                               removeNull=True) if users_output is not None else ""

    md = asset_md + vulnerabilities_md + software_md + services_md + users_md

    asset_output["Vulnerability"] = vulnerabilities_output
    asset_output["Software"] = software_output
    asset_output["Service"] = services_output
    asset_output["User"] = users_output

    endpoint = {
        "IP": asset_output["Addresses"],
        "MAC": asset_output["Hardware"],
        "HostName": asset_output["Aliases"],
        "OS": asset_output["OperatingSystem"]
    }

    context = {
        "Nexpose.Asset(val.AssetId==obj.AssetId)": asset_output,
        "Endpoint(val.IP==obj.IP)": endpoint
    }

    if cves_output:
        context["CVE(val.ID==obj.ID)"] = cves_output

    return {
        "Type": entryTypes["note"],
        "Contents": asset,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": context
    }


def get_asset_vulnerability_command(client: Client, asset_id: str, vulnerability_id: str):
    """
    Retrieve information about vulnerability findings on an asset.

    Args:
        client (Client): Client to use for API requests.
        asset_id (str): ID of the asset to retrieve information about.
        vulnerability_id (str): ID of the vulnerability to look for
    """
    vulnerability_data = client.get_asset_vulnerability(
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
    )

    if vulnerability_data is None:
        return "Vulnerability not found"

    vulnerability_headers = [
        "Id",
        "Title",
        "Severity",
        "RiskScore",
        "CVSS",
        "CVSSV3",
        "Published",
        "Added",
        "Modified",
        "CVSSScore",
        "CVSSV3Score",
        "Categories",
        "CVES"
    ]

    # Add extra info about vulnerability
    vulnerability_extra_data = client.get_vulnerability(asset_id)
    vulnerability_data.update(vulnerability_extra_data)

    vulnerability_outputs = replace_key_names(
        data=vulnerability_extra_data,
        name_mapping={
            "id": "Id",
            "title": "Title",
            "severity": "Severity",
            "riskScore": "RiskScore",
            "cvss.v2.vector": "CVSS",
            "cvss.v3.vector": "CVSSV3",
            "published": "Published",
            "added": "Added",
            "modified": "Modified",
            "cvss.v2.score": "CVSSScore",
            "cvss.v3.score": "CVSSV3Score",
            "categories": "Categories",
            "cves": "CVES",
        },
        recursive=True,  # TODO: Check if should be False
    )

    results_headers = [
        "Port",
        "Protocol",
        "Since",
        "Proof",
        "Status"
    ]

    results_output = []

    if vulnerability_data.get("results"):
        results_output = replace_key_names(
            data=vulnerability_data["results"],
            name_mapping={
                "port": "Port",
                "protocol": "Protocol",
                "since": "Since",
                "proof": "Proof",
                "status": "Status",
            },
            recursive=True,  # TODO: Check if should be False
        )

    # Remove HTML tags
    for result in results_output:
        result["Proof"] = re.sub("<.*?>", "", result["Proof"])

    solutions_headers = [
        "Type",
        "Summary",
        "Steps",
        "Estimate",
        "AdditionalInformation"
    ]

    # Add solutions data
    solutions_output = None
    solutions = client.get_asset_vulnerability_solution(asset_id, vulnerability_id)
    vulnerability_data["solutions"] = solutions

    if solutions:
        solutions_output = replace_key_names(
            data=solutions.get("resources"),
            name_mapping={
                "type": "Type",
                "summary.text": "Summary",
                "steps.text": "Steps",
                "estimate": "Estimate",
                "additionalInformation.text": "AdditionalInformation",
            },
            recursive=True,  # TODO: Check if should be False
        )

        for i, val in enumerate(solutions_output):
            solutions_output[i]["Estimate"] = str(
                iso8601_duration_as_minutes(solutions_output[i]["Estimate"])) + " minutes"

    vulnerabilities_md = tableToMarkdown("Vulnerability " + vulnerability_id, vulnerability_outputs,
                                         vulnerability_headers, removeNull=True)
    results_md = tableToMarkdown("Checks", results_output, results_headers, removeNull=True) if len(
        results_output) > 0 else ""
    solutions_md = tableToMarkdown("Solutions", solutions_output, solutions_headers,
                                   removeNull=True) if solutions_output is not None else ""

    md = vulnerabilities_md + results_md + solutions_md
    cves = []

    if vulnerability_outputs["CVES"] is not None and len(vulnerability_outputs["CVES"]) > 0:
        cves = [{
            "ID": cve
        } for cve in vulnerability_outputs["CVES"]]

    vulnerability_outputs["Check"] = results_output
    vulnerability_outputs["Solution"] = solutions_output

    asset = {
        "AssetId": asset_id,
        "Vulnerability": [vulnerability_outputs]
    }

    context = {
        "Nexpose.Asset(val.AssetId==obj.AssetId)": asset,
    }

    if len(cves) > 0:
        context["CVE(val.ID==obj.ID)"] = cves

    return {
        "Type": entryTypes["note"],
        "Contents": vulnerability_data,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": context
    }


def search_assets_command(client: Client, filter_query: Union[str, None] = None,
                          ip_addresses: Union[str, None] = None, hostnames: Union[str, None] = None,
                          risk_score: Union[str, None] = None, vulnerability_title: Union[str, None] = None,
                          sites: Union[Site, list[Site], None] = None, match: Union[str, None] = None,
                          sort: Union[str, None] = None, limit: Union[int, None] = None):
    """
    Retrieve a list of all assets with access permissions that match the provided search filters.

    Args:
        client (Client): Client to use for API requests.
        filter_query (str | None, optional): String based filters to use separated by ';'. Defaults to None.
        ip_addresses (str | None, optional): IP address(es) to filter for separated by ','. Defaults to None.
        hostnames (str | None, optional): Hostname(s) to filter for separated by ','. Defaults to None.
        risk_score (str | None, optional): Filter for risk scores that are higher than the provided value.
            Defaults to None.
        vulnerability_title (str | None, optional): Filter for vulnerability titles that contain the provided value.
            Defaults to None. Defaults to None.
        sites (Site | list[Site] | None, optional): Filter for assets that are under a specific site(s).
            Defaults to None.
        match (str | None, optional): Determine if the filters should match all or any of the filters.
            Can be either "all" or "any". Defaults to None (Results in using MATCH_DEFAULT_VALUE).
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    filters_data: list[Union[list[str], str]] = []

    if filter_query:
        filters_data.append(filter_query.split(";"))

    elif risk_score:
        filters_data.append("risk-score is-greater-than " + risk_score)

    elif vulnerability_title:
        filters_data.append("vulnerability-title contains " + vulnerability_title)

    elif sites:
        str_site_ids: str

        if isinstance(sites, list):
            str_site_ids = ",".join([site.id for site in sites])

        else:  # elif isinstance(sites, Site):
            str_site_ids = sites.id

        filters_data.append("site-id in " + str_site_ids)

    elif ip_addresses:
        ips = argToList(ip_addresses)

        for ip in ips:  # TODO: Change to `in <list of comma separated ip addresses>` instead if multiple filters?
            filters_data.append("ip-address is " + ip)

    elif hostnames:
        hostnames = argToList(hostnames)

        for hostname in hostnames:  # TODO: Change to `in <list of comma separated hostnames>` instead if multiple filters?
            filters_data.append("host-name is " + hostname)

    found_assets = []

    for filter_data in filters_data:
        found_assets.extend(
            client.search_assets(
                filters=convert_asset_search_filters(filter_data),
                match=match,
                sort=sort,
                limit=limit,
            )
        )

    if not found_assets:
        return "No assets were found"

    for asset in found_assets:
        last_scan = find_asset_last_change(asset)
        asset["LastScanDate"] = last_scan["date"]
        asset["LastScanId"] = last_scan["id"]
        site = get_site(asset["id"])
        asset["Site"] = site["name"] if site != "" else ""

    headers = [
        "AssetId",
        "Address",
        "Name",
        "Site",
        "Exploits",
        "Malware",
        "OperatingSystem",
        "RiskScore",
        "Assessed",
        "LastScanDate",
        "LastScanId"
    ]

    outputs = replace_key_names(
        data=found_assets,
        name_mapping={
            "id": "AssetId",
            "ip": "Address",
            "hostName": "Name",
            "Site": "Site",
            "vulnerabilities.exploits": "Exploits",
            "vulnerabilities.malwareKits": "Malware",
            "os": "OperatingSystem",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "RiskScore",
            "assessedForVulnerabilities": "Assessed",
            "LastScanDate": "LastScanDate",
            "LastScanId": "LastScanId",
        },
        recursive=True,  # TODO: Check if should be False
    )
    endpoints = [{"IP": asset["Address"], "HostName": asset["Name"], "OS": asset["OperatingSystem"]}
                 for asset in outputs]

    return {
        "Type": entryTypes["note"],
        "Contents": found_assets,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown("Nexpose assets", outputs, headers, removeNull=True),
        "EntryContext": {
            "Nexpose.Asset(val.AssetId==obj.AssetId)": outputs,
            "Endpoint(val.IP==obj.IP)": endpoints
        }
    }


def convert_asset_search_filters(search_filters: Union[str, list[str]]) -> list[dict]:
    """
    | Convert string-based asset search filters to dict-based asset search filters that can be used in Nexpose's API.
    |
    | Format specification can be found under "Search Criteria" on:
        https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses

    Args:
        search_filters (str | list[str]): List of string-based search filters.

    Returns:
        list(dict): List of the same search filters in a dict-based format.
    """
    if isinstance(search_filters, str):
        search_filters = [search_filters]

    range_operators = ["in-range", "is-between", "not-in-range"]
    normalized_filters = []

    for search_filter in search_filters:
        # Example: risk-score is-between 5,10
        #   _field = risk-score
        #   _operator = is-greater-than
        #   _value = 5,10
        _field, _operator, _value = search_filter.split(" ")
        values = argToList(_value)

        # Convert numbers to floats if values are numbers
        # TODO: Check if float conversion has any meaning, remove if not
        for i, value in enumerate(values):
            current_value = None
            try:
                current_value = float(value)

            except Exception:
                current_value = value
            value[i] = current_value

        filter_dict = {
            "field": _field,
            "operator": _operator,
        }

        if len(values) > 1:
            if _operator in range_operators:
                filter_dict["lower"] = values[0]
                filter_dict["upper"] = values[1]
            else:
                filter_dict["values"] = values
        else:
            filter_dict["value"] = values[0]

        normalized_filters.append(filter_dict)

    return normalized_filters


def get_assets_command(client: Client, sort: Union[str, None] = None, limit: Union[int, None] = None):
    """
    Retrieve a list of all assets.

    Args:
        client (Client): Client to use for API requests.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    assets = client.get_assets(
        sort=sort,
        limit=limit
    )

    if not assets:
        return "No assets found"

    for asset in assets:
        last_scan = find_asset_last_change(asset)
        asset["LastScanDate"] = last_scan["date"]
        asset["LastScanId"] = last_scan["id"]
        site = get_site(asset["id"])
        asset["Site"] = site["name"] if site != "" else ""

    headers = [
        "AssetId",
        "Address",
        "Name",
        "Site",
        "Exploits",
        "Malware",
        "OperatingSystem",
        "Vulnerabilities",
        "RiskScore",
        "Assessed",
        "LastScanDate",
        "LastScanId"
    ]

    outputs = replace_key_names(
        data=assets,
        name_mapping={
            "id": "AssetId",
            "ip": "Address",
            "hostName": "Name",
            "Site": "Site",
            "vulnerabilities.exploits": "Exploits",
            "vulnerabilities.malwareKits": "Malware",
            "os": "OperatingSystem",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "RiskScore",
            "assessedForVulnerabilities": "Assessed",
            "LastScanDate": "LastScanDate",
            "LastScanId": "LastScanId",
        },
        recursive=True,  # TODO: Check if should be False
    )

    endpoint = [{"IP": asset["Address"], "HostName": asset["Name"], "OS": asset["OperatingSystem"]}
                for asset in outputs]

    return {
        "Type": entryTypes["note"],
        "Contents": assets,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown("Nexpose assets", outputs, headers, removeNull=True),
        "EntryContext": {
            "Nexpose.Asset(val.AssetId==obj.AssetId)": outputs,
            "Endpoint(val.IP==obj.IP)": endpoint
        }
    }


def get_scan_command(client: Client, scan_ids: Union[str, list[str]]):
    """
    Retrieve information about a specific or multiple scans.

    Args:
        client (Client): Client to use for API requests.
        scan_ids (str | list): ID of the scan to retrieve.

    Returns:
        dict: API response with information about a specific scan.
    """
    scans = []
    for scan_id in scan_ids:
        scan = client.get_scan(scan_id)

        if not scan:
            return "Scan not found"

        scan_entry = get_scan_entry(scan)
        scans.append(scan_entry)

    return scans


def normalize_scan_data(scan: dict) -> dict:
    """
    Normalizes scan data received from the API to a format that will be displayed in the UI.

    Args:
        scan (dict): Scan data as it was received from the API.

    Returns:
        dict: Scan data in a normalized format that will be displayed in the UI.
    """
    scan_output = replace_key_names(
        data=scan,
        name_mapping={
            "id": "Id",
            "scanType": "ScanType",
            "scanName": "ScanName",
            "startedBy": "StartedBy",
            "assets": "Assets",
            "duration": "TotalTime",
            "endTime": "Completed",
            "status": "Status",
            "message": "Message",
        },
        recursive=False,
    )

    scan_output["TotalTime"] = str(iso8601_duration_as_minutes(scan_output["TotalTime"])) + " minutes"

    return scan_output


def get_scan_entry(scan: dict) -> dict:
    """
    Generate entry data from scan data (as received from the API).

    Args:
        scan (dict): Scan data as it was received from the API.

    Returns:
        dict: Scan data in a normalized format that will be displayed in the UI.
    """
    scan_output = normalize_scan_data(scan)

    vuln_headers = [
        "Critical",
        "Severe",
        "Moderate",
        "Total"
    ]

    vuln_output = replace_key_names(
        data=scan["vulnerabilities"],
        name_mapping={
            "critical": "Critical",
            "severe": "Severe",
            "moderate": "Moderate",
            "total": "Total",
        },
        recursive=True,  # TODO: Check if should be False
    )

    scan_hr = tableToMarkdown(
        name="Nexpose scan " + str(scan["id"]),
        t=scan_output,
        headers=[
            "Id",
            "ScanType",
            "ScanName",
            "StartedBy",
            "Assets",
            "TotalTime",
            "Completed",
            "Status",
            "Message",
        ],
        removeNull=True)

    vulnerability_hr = tableToMarkdown("Vulnerabilities", vuln_output, vuln_headers, removeNull=True)
    hr = scan_hr + vulnerability_hr

    scan_output["Vulnerabilities"] = vuln_output

    return {
        "Type": entryTypes["note"],
        "Contents": scan,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": hr,
        "EntryContext": {
            "Nexpose.Scan(val.Id==obj.Id)": scan_output,
        }
    }


def create_site_command(client: Client, name: str, description: Union[str, None] = None,
                        assets: Union[list[str], None] = None, site_importance: Union[SiteImportance, None] = None,
                        template_id: Union[str, None] = None):
    """
    Create a new site.

    Args:
        client (Client): Client to use for API requests.
        name (str): Name of the site. Must be unique.
        description (str | None, optional): Description of the site. Defaults to None.
        assets (list[str] | None, optional): List of asset IDs to be included in site scans. Defaults to None.
        site_importance (SiteImportance | None, optional): Importance of the site.
            Defaults to None (results in using API's default - "normal").
        template_id (str | None, optional): The identifier of a scan template.
            Defaults to None (results in using default scan template).
    """
    response = client.create_site(name, description, assets, site_importance.name.lower(), template_id)

    output = {
        "Id": response["id"]
    }

    md = tableToMarkdown("New site created", output)

    return {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": {
            "Nexpose.Site(val.Id==obj.Id)": output,
        }
    }


def delete_site_command(client: Client, site: Site):
    """
    Delete a site.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to delete.
    """
    response = client.delete_site(site.id)

    return {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": f"Site ID {site.id} has been deleted."
    }


def get_sites_command(client: Client, sort: Union[str, None] = None, limit: Union[int, None] = None):
    """
    Retrieve a list of sites.

    Args:
        client (Client): Client to use for API requests.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    sites = client.get_sites(
        sort=sort,
        limit=limit
    )

    if not sites:
        return "No sites found"

    headers = [
        "Id",
        "Name",
        "Assets",
        "Vulnerabilities",
        "Risk",
        "Type",
        "LastScan"
    ]

    outputs = replace_key_names(
        data=sites,
        name_mapping={
            "id": "Id",
            "name": "Name",
            "assets": "Assets",
            "vulnerabilities.total": "Vulnerabilities",
            "riskScore": "Risk",
            "type": "Type",
            "lastScanTime": "LastScan",
        },
        recursive=True,  # TODO: Check if should be False
    )

    return {
        "Type": entryTypes["note"],
        "Contents": sites,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown("Nexpose sites", outputs, headers, removeNull=True),
        "EntryContext": {
            "Nexpose.Site(val.Id==obj.Id)": outputs,
        }
    }


def get_report_templates_command(client: Client):
    """
    Retrieve information about all available report templates.

    Args:
        client (Client): Client to use for API requests.
    """
    response_data = client.get_report_templates()

    if not response_data.get("resources"):
        return "No templates found"

    headers = [
        "Id",
        "Name",
        "Description",
        "Type"
    ]

    outputs = replace_key_names(
        data=response_data["resources"],
        name_mapping={
            "id": "Id",
            "name": "Name",
            "description": "Description",
            "type": "Type",
        },
        recursive=True,  # TODO: Check if should be False
    )

    return {
        "Type": entryTypes["note"],
        "Contents": response_data,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown("Nexpose templates", outputs, headers, removeNull=True),
        "EntryContext": {
            "Nexpose.Template(val.Id==obj.Id)": outputs,
        }
    }


def create_assets_report_command(client: Client, asset_ids: list[str], template_id: Union[str, None] = None,
                                 report_name: Union[str, None] = None, report_format: Union[str, None] = None,
                                 download_immediately: Union[bool, None] = None):
    """
    Create a report about specific assets.

    Args:
        client (Client): Client to use for API requests.
        asset_ids (list[str]): List of assets to include in the report.
        template_id (str | None, optional): ID of report template to use. Defaults to None.
        report_name (str): Name for the report that will be generated.
        report_format (str): Format of the report that will be generated.  # TODO: Add a list of available formats to use.
        download_immediately: Union[bool, None] = Whether to download the report automatically after creation.
    """
    if not report_name:
        report_name = "report " + str(datetime.now())

    if not report_format:
        report_format = "pdf"

    if download_immediately is None:
        download_immediately = True

    report_id = str(client.create_report_config(
        scope={"assets": [int(asset_id) for asset_id in asset_ids]},
        # TODO: Check if conversion to int is actually needed
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
    ).get("id"))

    instance_id = str(client.create_report(report_id).get("id"))

    context = {
        "Name": report_name,
        "ID": report_id,
        "InstanceID": instance_id,
        "Format": report_format,
    }
    hr = tableToMarkdown("Report Information", context)

    if download_immediately:
        try:
            # Wait for the report to be completed
            time.sleep(REPORT_DOWNLOAD_WAIT_TIME)

            return download_report_command(
                client=client,
                report_id=report_id,
                instance_id=instance_id,
                report_name=report_name,
                report_format=report_format,
            )

        except Exception as e:
            # If we received 404 it could mean that the report generation process has not finished yet. in that case
            # we'll return the report's info to enable users to query for the report's status and download it.
            if "404" not in str(e):
                raise

    return CommandResults(
        readable_output=hr,
        outputs_prefix="Nexpose.Report",
        outputs=context,
        outputs_key_field=["ID", "InstanceID"],
    )


def create_sites_report_command(client: Client, sites: list[Site], template_id: Union[str, None] = None,
                                report_name: Union[str, None] = None, report_format: Union[str, None] = None,
                                download_immediately: Union[bool, None] = None):
    """
    Create a report about specific sites.

    Args:
        client (Client): Client to use for API requests.
        sites (list[Site]): List of sites to create the report about.
        template_id (str | None, optional): ID of report template to use. Defaults to None.
        report_name (str): Name for the report that will be generated.
        report_format (str): Format of the report that will be generated.  # TODO: Add a list of available formats to use.
        download_immediately: Union[bool, None] = Whether to download the report automatically after creation.
    """
    if not report_name:
        report_name = "report " + str(datetime.now())

    if not report_format:
        report_format = "pdf"

    if download_immediately is None:
        download_immediately = True

    report_id = str(client.create_report_config(
        scope={"sites": sites},
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
    ).get("id"))

    instance_id = str(client.create_report(report_id).get("id"))

    context = {
        "Name": report_name,
        "ID": report_id,
        "InstanceID": instance_id,
        "Format": report_format,
    }

    hr = tableToMarkdown("Report Information", context)

    if download_immediately:
        try:
            # Wait for the report to be completed
            time.sleep(REPORT_DOWNLOAD_WAIT_TIME)

            return download_report_command(
                client=client,
                report_id=report_id,
                instance_id=instance_id,
                report_name=report_name,
                report_format=report_format,
            )

        except Exception as e:
            # If we received 404 it could mean that the report generation process has not finished yet. in that case
            # we'll return the report's info to enable users to query for the report's status and download it.
            if "404" not in str(e):
                raise

    return CommandResults(
        readable_output=hr,
        outputs_prefix="Nexpose.Report",
        outputs=context,
        outputs_key_field=["ID", "InstanceID"],
    )


def create_scan_report_command(client: Client, scan_id: str, template_id: Union[str, None] = None,
                               report_name: Union[str, None] = None, report_format: Union[str, None] = None,
                               download_immediately: Union[bool, None] = None):
    """
        Create a report about specific sites.

        Args:
            client (Client): Client to use for API requests.
            scan_id (scan): ID of the scan to create a report on.
            template_id (str | None, optional): ID of report template to use. Defaults to None.
            report_name (str): Name for the report that will be generated.
            report_format (str): Format of the report that will be generated.  # TODO: Add a list of available formats to use.
            download_immediately: Union[bool, None] = Whether to download the report automatically after creation.
        """
    report_id = client.create_report_config(
        scope={"scan": scan_id},
        template_id=template_id,
        report_name=report_name,
        report_format=report_format,
    ).get("id")

    instance_id = str(client.create_report(report_id).get("id"))

    context = {
        "Name": report_name,
        "ID": report_id,
        "InstanceID": instance_id,
        "Format": report_format,
    }

    hr = tableToMarkdown("Report Information", context)

    if download_immediately:
        # Wait for the report to be completed
        time.sleep(REPORT_DOWNLOAD_WAIT_TIME)

        try:
            return download_report_command(
                client=client,
                report_id=report_id,
                instance_id=instance_id,
                report_name=report_name,
                report_format=report_format,
            )

        except Exception as e:
            # If we received 404 it could mean that the report generation process has not finished yet. in that case
            # we'll return the report's info to enable users to query for the report's status and download it.
            if "404" not in str(e):
                raise

    return CommandResults(
        readable_output=hr,
        outputs_prefix="Nexpose.Report",
        outputs=context,
        outputs_key_field=["ID", "InstanceID"],
    )


def download_report_command(client: Client, report_id: str, instance_id: str,
                            report_name: Union[str, None], report_format: str) -> dict:
    """
    Download a report file.

    Args:
        client (Client): Client to use for API requests.
        report_id (str): ID of the report to download.
        instance_id (str): ID of the report instance.
        report_name (str | None, optional): Name to give the generated report file.
            Defaults to None (results in using a "report <date>" format as a name).
        report_format (str): File format to use for the generated report.

    Returns:
        dict: A dict generated by `CommonServerPython.fileResult` representing a War Room entry.
    """
    # TODO: Check if format can actually be changed from the default PDF received from Nexpose. Delete if not?

    if not report_name:
        report_name = f"report {str(datetime.now())}"  # TODO: Move to a const?

    report_data = client.download_report(
        report_id=report_id,
        instance_id=instance_id
    )

    return fileResult(
        filename=f"{report_name}.{report_format}",
        data=report_data,
        file_type=entryTypes["entryInfoFile"],
    )


def get_generated_report_status_command(client: Client, report_id: str, instance_id: str):
    """
    Retrieve information about a generated report's status.

    Args:
        client (Client): Client to use for API requests.
        report_id (str): ID of the report to retrieve information about.
        instance_id (str): ID of the report instance to retrieve information about.
    """

    response = client.get_report_history(report_id, instance_id)

    context = {
        "ID": report_id,
        "InstanceID": instance_id,
        "Status": response.get("status", "unknown"),
    }

    hr = tableToMarkdown("Report Generation Status", context)

    return CommandResults(
        readable_output=hr,
        outputs_prefix="Nexpose.Report",
        outputs=context,
        outputs_key_field=["ID", "InstanceID"],
        raw_response=response,
    )


def start_assets_scan_command(client: Client, ips: Union[str, list, None] = None,
                              hostnames: Union[str, list, None] = None, scan_name: Union[str, None] = None):
    """
    | Start a scan on the provided assets.
    |
    | Note: Both `ips` and `hostnames` are optional, but at least one of them must be provided.

    Args:
        client (Client): Client to use for API requests.
        ips (str | list | None, optional): IP(s) of assets to scan. Defaults to None
        hostnames (str | list | None, optional): Hostname(s) of assets to scan. Defaults to None
        scan_name (str | None): Name to set for the new scan.
            Defaults to None (Results in using a "scan <date>" format).
    """
    if not (ips or hostnames):
        raise ValueError("At least one of `ips` and `hostnames` must be provided")

    if not scan_name:
        scan_name = f"scan {datetime.now()}"

    if isinstance(ips, str):
        ips = [ips]

    if isinstance(hostnames, str):
        hostnames = [hostnames]

    if ips:
        asset_filter = "ip-address is " + ips[0]

    else:  # elif hostnames
        asset_filter = "host-name is " + hostnames[0]

    asset = client.search_assets(filters=convert_asset_search_filters(asset_filter), match="all")

    if not asset:
        return "Could not find assets"

    site = get_site(asset[0]["id"])

    if site is None or "id" not in site:  # TODO: Check if `site` can actually be None
        return "Could not find site"

    hosts = []

    if ips:
        hosts.extend(ips)

    if hostnames:
        hosts.extend(hostnames)

    scan_response = client.start_site_scan(
        site_id=site["id"],
        scan_name=scan_name,
        hosts=hosts
    )

    if "id" not in scan_response:
        return "Could not start scan"

    return get_scan_entry(client.get_scan(scan_response["id"]))


def start_site_scan_command(client: Client, site: Site, scan_name: Union[str, None], hosts: Union[list[str], None]):
    """
    Start a scan for a specific site.

    Args:
        client (Client): Client to use for API requests.
        site (Site): Site to start a scan on.
        scan_name (str | None): Name to set for the new scan.
            Defaults to None (Results in using a "scan <date>" format).
        hosts (list[str] | None): Hosts to scan. Defaults to None (Results in scanning all hosts).
    """
    if not scan_name:
        scan_name = f"scan {datetime.now()}"

    if not hosts:
        assets = client.get_site_assets(site.id)
        hosts = [asset["ip"] for asset in assets]

    scan_response = client.start_site_scan(
        site_id=site.id,
        scan_name=scan_name,
        hosts=hosts
    )

    if not scan_response or "id" not in scan_response:
        return "Could not start scan"

    scan_data = client.get_scan(scan_response.get("id"))
    return get_scan_entry(scan_data)


def get_scans_command(client: Client, active: Union[bool, None] = None, sort: Union[str, None] = None,
                      limit: Union[int, None] = None):
    """
    Retrieve a list of all scans.

    Args:
        client (Client): Client to use for API requests.
        active (bool | None, optional): Whether to return active scans or not. Defaults to False.
        sort (str | None, optional): Sort results by fields. Uses a `property[,ASC|DESC]...` format. Defaults to None.
        limit (int | None, optional): Limit the number of scans to return. None means to not use a limit.
            Defaults to None.
    """
    scans: list = client.get_scans(
        active=active,
        sort=sort,
        limit=limit,
    )

    if not scans:
        return "No scans found"

    normalized_scans = [normalize_scan_data(scan) for scan in scans]

    scan_hr = tableToMarkdown(
        name="Nexpose scans",
        t=normalized_scans,
        headers=[
            "Id",
            "ScanType",
            "ScanName",
            "StartedBy",
            "Assets",
            "TotalTime",
            "Completed",
            "Status",
            "Message",
        ],
        removeNull=True)

    return {
        "Type": entryTypes["note"],
        "Contents": scans,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": scan_hr,
        "EntryContext": {
            "Nexpose.Scan(val.Id==obj.Id)": normalized_scans,
        }
    }


def update_scan_command(client: Client, scan_id: str, scan_status: ScanStatus):
    """
    Update status for a specific scan.

    Args:
        client (Client): Client to use for API requests.
        scan_id (str): ID of the scan to update.
        scan_status (ScanStatus): Status to set the scan to.
    """
    response = client.update_scan_status(scan_id, scan_status.name.lower())

    return {
        "Type": entryTypes["note"],
        "Contents": response,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["text"],
        "HumanReadable": f"Successfully updated scan status to \"{scan_status.name.lower()}\""
    }


def find_valid_params(**kwargs):
    """
    A function for filtering kwargs to remove keys with a None value.

    Args:
        kwargs: A collection of keyword args to filter.

    Returns:
        dict: A dictionary containing only keywords with a value that isn't None.
    """
    new_kwargs = {}

    for key, value in kwargs.items():
        if value:
            new_kwargs[key] = value

    return new_kwargs


def main():
    try:
        args = demisto.args()
        params = demisto.params()
        command = demisto.command()
        handle_proxy()

        client = Client(
            url=params.get("server"),
            username=params["credentials"].get("identifier"),
            password=params["credentials"].get("password"),
            token=params.get("token"),
            verify=not params.get("unsecure")
        )

        # TODO: Implement a connection test to assure credentials are valid, to avoid repeating requests the can lead to a locked account?

        if command == "test-module":
            client.get_assets(page_size=1, limit=1)
            results = "ok"
        elif command == "nexpose-get-assets":
            results = get_assets_command(
                client=client,
                sort=args.get("sort"),
                limit=args.get("limit")
            )
        elif command == "nexpose-get-asset":
            results = get_asset_command(
                client=client,
                asset_id=args.get("id")
            )
        elif command == "nexpose-get-asset-vulnerability":
            results = get_asset_vulnerability_command(
                client=client,
                asset_id=args.get("id"),
                vulnerability_id=args.get("vulnerabilityId"),
            )
        elif command == "nexpose-search-assets":
            sites: list[Site] = []

            for site_id in argToList(args.get("siteIdIn")):
                sites.append(Site(site_id=site_id, client=client))

            for site_name in argToList(args.get("siteNameIn")):
                sites.append(Site(site_name=site_name, client=client))

            results = search_assets_command(
                client=client,
                filter_query=args.get("query"),
                ip_addresses=args.get("ipAddressIs"),
                hostnames=args.get("hostNameIs"),
                risk_score=args.get("riskScoreHigherThan"),
                vulnerability_title=args.get("vulnerabilityTitleContains"),
                sites=sites,
                match=args.get("match"),
                sort=args.get("sort"),
                limit=arg_to_number(args.get("limit")),
            )
        elif command == "nexpose-get-scan":
            results = get_scan_command(
                client=client,
                scan_ids=argToList(str(args.get(id))),
            )
        elif command == "nexpose-get-scans":
            results = get_scans_command(
                client=client,
                active=args.get("active"),
                sort=args.get("sort"),
                limit=args.get("limit"),
            )
        elif command == "nexpose-get-sites":
            results = get_sites_command(
                client=client,
                sort=args.get("sort"),
                limit=args.get("limit"),
            )
        elif command == "nexpose-get-report-templates":
            results = get_report_templates_command(
                client=client,
            )
        elif command == "nexpose-create-assets-report":
            results = create_assets_report_command(
                client=client,
                asset_ids=argToList(args.get("assets")),
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=args.get("format"),
                download_immediately=argToBoolean(args.get("download_immediately"))
            )
        elif command == "nexpose-create-sites-report":
            sites_list = [Site(site_id=site_id, client=client) for site_id in argToList(args.get("sites"))]
            sites_list.extend(
                [Site(site_name=site_name, client=client) for site_name in argToList(args.get("site_names"))]
                # TODO: Add `site_names` to yaml.
            )

            results = create_sites_report_command(
                client=client,
                sites=sites_list,
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=args.get("format"),
                download_immediately=argToBoolean(args.get("download_immediately")),
            )
        elif command == "nexpose-create-scan-report":
            results = create_scan_report_command(
                client=client,
                scan_id=args.get("scans"),
                template_id=args.get("template"),
                report_name=args.get("name"),
                report_format=args.get("format"),
                download_immediately=argToBoolean(args.get("download_immediately")),
            )
        elif command == "nexpose-get-report-status":
            results = get_generated_report_status_command(
                client=client,
                report_id=args.get("report_id"),
                instance_id=args.get("instance_id")
            )
        elif command == "nexpose-download-report":
            results = download_report_command(
                client=client,
                report_id=args.get("report_id"),
                instance_id=args.get("instance_id"),
                report_name=args.get("name"),
                report_format=args.get("format", "pdf"),
            )
        elif command == "nexpose-start-site-scan":
            results = start_site_scan_command(
                client=client,
                site=Site(
                    site_id=args.get("id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
                scan_name=args.get("name"),
                hosts=argToList(args.get("hosts")),
            )
        elif command == "nexpose-start-assets-scan":
            results = start_assets_scan_command(
                client=client,
                ips=args.get("IPs"),
                hostnames=args.get("hostNames"),
                scan_name=args.get("name"),
            )
        elif command == "nexpose-create-site":
            results = create_site_command(
                client=client,
                name=args.get("name"),
                description=args.get("description"),
                assets=argToList(args.get("assets")),
                site_importance=SiteImportance(args.get("importance").upper()),
                template_id=args.get("scanTemplateId"),
            )
        elif command == "nexpose-delete-site":
            results = delete_site_command(
                client=client,
                site=Site(
                    site_id=args.get("id"),
                    site_name=args.get("site_name"),
                    client=client,
                ),
            )
        elif command == "nexpose-stop-scan":
            results = update_scan_command(
                client=client,
                scan_id=args.get("id"),
                scan_status=ScanStatus.STOP,
            )
        elif command == "nexpose-pause-scan":
            results = update_scan_command(
                client=client,
                scan_id=args.get("id"),
                scan_status=ScanStatus.PAUSE,
            )
        elif command == "nexpose-resume-scan":
            results = update_scan_command(
                client=client,
                scan_id=args.get("id"),
                scan_status=ScanStatus.RESUME,
            )
        else:
            raise NotImplementedError(f"Command {command} not implemented")

        return_results(results)

    except Exception as e:
        LOG(e)
        LOG.print_log(False)
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
