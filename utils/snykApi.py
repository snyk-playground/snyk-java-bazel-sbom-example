# import json
import json
from time import sleep
import requests
# from requests.exceptions import HTTPError
# import time

from utils.helper import get_snyk_token

SNYK_TOKEN = get_snyk_token()

rest_headers = {'Content-Type': 'application/vnd.api+json', 'Authorization': f'token {SNYK_TOKEN}'}
v1Headers = {'Content-Type': 'application/json; charset=utf-8', 'Authorization': f'token {SNYK_TOKEN}'}
rest_version = '2024-10-15'

def create_request_method(method):
    methods = {
        'GET': requests.get,
        'POST': requests.post,
        'PUT': requests.put,
        'DELETE': requests.delete,
        'PATCH': requests.patch,
    }

    http_method = methods.get(method.upper())
    
    return http_method


# Paginate through Snyk's API endpoints with retry and backoff
def pagination_snyk_rest_endpoint(method, url, *args):
    retries = 3
    delay = 5
    http_method = create_request_method(method)
    if any(args):
        for attempt in range(retries):
            try:
                api_response = http_method(url, headers=rest_headers, data=json.dumps(args[0]))
                api_response.raise_for_status()
                return api_response.json()
            except requests.RequestException as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    sleep(delay)
                else:
                    print("All attempts failed.")
                    raise
    else:
        has_next_link = True
        data = []
        while has_next_link:
            for attempt in range(retries):
                try:
                    api_response = http_method(url, headers=rest_headers)
                    api_data = api_response.json()['data']
                    data.extend(api_data)
                    # If the response status is 429, handle the rate limit
                    if api_response.status_code == 429:
                        print(f"Rate limit exceeded. Waiting for 60 seconds.")
                        sleep(61)
                        continue
                except requests.RequestException as e:
                    print(f"Attempt {attempt + 1} failed: {e}")
                    if attempt < retries - 1:
                        sleep(delay)
                    else:
                        print("All attempts failed.")
                        raise
                
                # Check if next page exist and set url if it does.  If not, exit and return issuesData
                try:
                    api_response.json()['links']['next']
                    url = 'https://api.snyk.io' + api_response.json()['links']['next']
                except:
                    has_next_link = False
                    return data
    

# Return user invitation list
def get_pending_user_list(org_id):
    url = f'https://api.snyk.io/rest/orgs/{org_id}/invites?version={rest_version}'
    
    pending_user_list = pagination_snyk_rest_endpoint('GET', url)
    
    return pending_user_list


# Get group membership
def get_org_memberships(org_id):
    url = f'https://api.snyk.io/rest/orgs/{org_id}/memberships?version={rest_version}&limit=100'
    
    org_membership_response = pagination_snyk_rest_endpoint('GET', url)
    
    return org_membership_response

def get_group_memberships(group_id):
    url = f'https://api.snyk.io/rest/group/{group_id}/memberships?version={rest_version}&limit=100'
    
    org_membership_response = pagination_snyk_rest_endpoint('GET', url)
    
    return org_membership_response
    
    
def create_group_membership_for_user(group_id, role_id, user_id):
    url = f'https://api.snyk.io/rest/groups/{group_id}/memberships?version={rest_version}'
    body = {"data": {"relationships": {"group": {"data": {"id": group_id,"type": "group"}},"role": {"data": {"id": role_id,"type": "group_role"}},"user": {"data": {"id": user_id,"type": "user"}}},"type": "group_membership"}}
    
    group_membership_response = pagination_snyk_rest_endpoint('POST', url, body)
    
    return group_membership_response

def create_sbom_test_run(org_id, sbom_data):
    url = f'https://api.snyk.io/rest/orgs/{org_id}/sbom_tests?version=2024-10-15~beta'
    body = {"data": {"type": "sbom_test","attributes": {"sbom":sbom_data}}}
    sbom_test_run_response = pagination_snyk_rest_endpoint('POST', url, body)
    return sbom_test_run_response

def get_sbom_test_run_status(org_id, sbom_test_run_id):
    url = f'https://api.snyk.io/rest/orgs/{org_id}/sbom_tests/{sbom_test_run_id}?version=2024-10-15~beta'
    sbom_test_run_status_response = pagination_snyk_rest_endpoint('GET', url)
    print("SBOM test run status response:", sbom_test_run_status_response)
    return sbom_test_run_status_response

# Return all Snyk orgs in group
def get_snyk_orgs(groupId):
    url = f'https://api.snyk.io/rest/groups/{groupId}/orgs?version={rest_version}&limit=100'

    org_data = pagination_snyk_rest_endpoint('GET', url)
    
    return org_data


# Get cpp projects from all Snyk Orgs.
def get_cpp_snyk_projects_for_target(org_id, target_id):
    url = f'https://api.snyk.io/rest/orgs/{org_id}/projects/?version={rest_version}&limit=100&types=nuget%2Ccpp&target_id={target_id}'
    
    cpp_project_data = pagination_snyk_rest_endpoint('GET', url)
    
    return cpp_project_data


# Delete a Snyk project
# def delete_snyk_project(org_id, project_id):
#     url = f'https://api.snyk.io/rest/orgs/{org_id}/projects/{project_id}?version={rest_version}'
    
#     delete_project_response = pagination_snyk_rest_endpoint('DELETE', url)
    
#     return delete_project_response


# Add a member to an organization within a group
def add_member_to_snyk_organization(group_id, org_id, user_id, role):
    print(f"Adding user to Snyk organization.")
    url = f'https://api.snyk.io/v1/group/{group_id}/org/{org_id}/memebers'
    body = {"userId": user_id, "role": role}
    try:
        add_member_response = requests.post(url, headers=v1Headers, data=json.dumps(body))
        if add_member_response.status_code == 200:
            print("User added successfully.")
            return True
    except:
        print(f"Add user endpoint failed with the following error code: {add_member_response.status_code}.  Here is the error: {add_member_response} ") 
        return False, add_member_response