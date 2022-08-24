"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from email import header
import string
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import requests
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(
            base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth
        )

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API

    def appliance_list_request(self, offset: int = None, limit: int = None):
        params = assign_params(offset=offset, limit=limit)
        headers = self._headers

        response = self._http_request(
            "GET",
            url_suffix="vnms/cloud/systems/getAllAppliancesBasicDetails",
            full_url="https://cloud-demo.versa-networks.com:9182/vnms/cloud/systems/getAllAppliancesBasicDetails",
            params=params,
            headers=headers,
        )

        return response

    def organization_list_request(self, offset: int = None, limit: int = None):
        params = assign_params(limit=limit, offset=offset)
        headers = self._headers

        response = self._http_request(
            "GET", "nextgen/organization", params=params, headers=headers
        )

        return response

    def appliances_list_by_organization_request(self, organization_name: string = None, offset: int = None, limit: int = None):
        params = assign_params(organization_name=organization_name, offset=offset, limit=limit)
        headers = self._headers
        #TODO: debug - check 'organization_name'
        response = self._http_request(
            "GET",
            f"vnms/appliance/filter/{organization_name}", params=params, headers=headers,
        )

        return response


""" HELPER FUNCTIONS """


def get_offset(page: int, page_size: int):
    """Determine offset according to 'page' and 'page_size' command args

    :return: offset
    :rtype: int
    """
    if not page and not page_size:
        return 1
    elif page and not page_size:
        return page
    elif page_size and not page:
        return page_size
    else:
        return page * page_size


""" COMMAND FUNCTIONS """


def appliance_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", 50))
    offset = get_offset(page, page_size)

    response = client.appliance_list_request(offset, limit)
    command_results = CommandResults(
        outputs_prefix="VersaDirector.Appliance",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            "Appliance List",
            t=response,
            headers=["name", "branchID", "ipAddress", "appType"],
        ),
    )

    return command_results


def organization_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", 50))
    offset = get_offset(page, page_size)

    # extract 'applianceuuid' list from 'appliances' dictionaty
    response = client.organization_list_request(offset, limit)
    appliances = []
    for appliance in response[0].get("appliances"):
        appliances.append(appliance.get("applianceuuid"))
    response[0]["appliances"] = appliances

    command_results = CommandResults(
        outputs_prefix="VersaDirector.Organization",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Organization List",
            t=response,
            headers=["name", "id", "parent", "appliances", "cpeDeploymentType", "uuid"],
        ),
    )

    return command_results


def appliances_list_by_organization_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get("organization_name")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit", 50))
    offset = get_offset(page, page_size)

    if not organization_name:
        organization_name = demisto.params().get("organization_name")
        if not organization_name:
            pass #TODO: ERROR

    response = client.appliances_list_by_organization_request(organization_name, offset, limit)

    command_results = CommandResults(
        outputs_prefix="VersaDirector.Appliance",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
        readable_output=tableToMarkdown(
            name="Organization List",
            t=response,
            headers=['appliances'],
            json_transform_mapping={'appliances': JsonTransformer(keys=['name', 'uuid', 'applianceName'])}
        ),
    )

    return command_results


def test_module(client: Client) -> str:

    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(
            e
        ):  # TODO: make sure you capture authentication errors
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO: make sure you properly handle authentication
    # api_key = demisto.params().get('credentials', {}).get('password')

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get("url")
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # get the service API url
    # base_url = urljoin(demisto.params()['url'], '/api/v1')

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    username = params["credentials"]["identifier"]
    password = params["credentials"]["password"]

    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        credentials = f"{username}:{password}"
        auth_header = f"Basic {b64_encode(credentials)}"
        headers = {
            "Authorization": auth_header,
        }

        client = Client(
            server_url=url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            auth=(username, password),
        )

        commands = {
            "vd-appliance-list": appliance_list_command,
            "vd-organization-list": organization_list_command,
            "vd-organization-appliance-list": appliances_list_by_organization_command,
        }

        if command == "test-module":
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
