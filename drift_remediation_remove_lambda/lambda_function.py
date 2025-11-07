# lambda_function.py
import os
import json
import boto3
import logging
import time
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# CONFIG
REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_ID = os.environ.get("AGENT_ID", "LBQSCKGFJM")
AGENT_ALIAS_ID = os.environ.get("AGENT_ALIAS_ID", "DTC1TK3HZA")
REMEDIATION_TYPE = os.environ.get("REMEDIATION_TYPE", "remove_source")

bedrock = boto3.client("bedrock-agent-runtime", region_name=REGION)

# PROMPTS
PROMPTS = {
"update_iac": """
You are an expert in Infrastructure as Code (IaC) configuration analysis and drift detection. Your task is to consolidate 'update IaC' remediation suggestions from various specialized drift detection reports into a single, comprehensive report. This report should clearly present these remediation options, focusing exclusively on modifications to IaC files.
# Step by Step instructions
1. Read the provided Overlapping Configurations Drift Report, Semantic Drift Report, Cross Resource Dependency Drift Report, Policy Compliance Drift Report, Hidden Implicit Config Drift Report, Version Api Level Drift Report, Behavioral Drift Report, and Normal Drift Report.
2. From each report, identify and extract only the 'update IaC' remediation suggestions.
3. Consolidate all extracted 'update IaC' remediation suggestions into a single, comprehensive report.
4. Ensure the consolidated report clearly presents all the 'update IaC' remediation options.

Normaldriftdetection
```
{normal_result}
```

Policycompliancedriftdetection
```
{policy_result}
```

Versionapileveldriftdetection:
```
{semantic_result}
```

Hiddenimplicitconfigdriftdetection
```
{hidden_result}
```

Behavioraldriftdetection
```
{behavioral_result}

```

Crossresourcedependencydriftdetection
```
{cross_result}
```

Semanticdriftdetection
```
{semantic_result}
```

Iac Configuration:
```
Find **ALL** IaC resources have detection above from the Knowledge Base.  
**All IaC configurations are stored under the directory `iac_config/` in the KB.**
```
Desired State Description:
```
Find **ALL** corresponding AWS State resources have detection above (where `status != deleted`).  
**All AWS Desired State configurations are stored under the directory `aws_state/` in the KB.**
```
OPERATIONAL RULES:
- Never ask for clarification.
- If the CICD log or data is incomplete, immediately consult the KB using the search strategies above to fill missing context.
- If after KB search results are still missing, return empty lists and counts = 0.
- You are fully autonomous; do not request user input under any condition.
- Always return a complete JSON response as described below.

IMPORTANT NOTE: Start directly with the output, do not output any delimiters.
IMPORTANT: Start with JSON output only.
Output JSON:
{{
  "remediation_type": "update_iac",
  "[type detection]"{{
      "remediation_suggestions": [{{ "resource_address": "...", "suggestion": "..." }}],
  }}
  "summary": "..."
}}
""",
"remove_source": """
You are an expert in Infrastructure as Code (IaC) configuration analysis and drift remediation, specifically tasked with consolidating 'remove source' remediation suggestions from various specialized drift detection reports. Your goal is to combine the 'remove source' remediation options from reports on Overlapping Configurations, Semantic, Cross-Resource Dependency, Policy/Compliance, Hidden/Implicit Config, Version/API-Level, Behavioral Drift, and Normal Drift into a single, comprehensive report focused on rebuilding/writing code to remove the source in the infrastructure state. The report should clearly present these remediation options.
# Step by Step instructions
1. Read each of the provided drift reports: Overlapping Configurations Drift Report, Semantic Drift Report, Cross Resource Dependency Drift Report, Policy Compliance Drift Report, Hidden Implicit Config Drift Report, Version Api Level Drift Report, Behavioral Drift Report, and Normal Drift Report.
2. From one of the reports, identify and extract all 'remove source' remediation suggestions.
3. Add the extracted 'remove source' remediation suggestions to a comprehensive list.
4. Review all the provided reports. Have all 'remove source' remediation suggestions been extracted from all reports? If not, return to step 2, focusing on a report that has not yet been fully processed.
5. Compile all identified 'remove source' remediation suggestions into a single, comprehensive report, ensuring clear presentation of these options for rebuilding/writing code to remove the source in the infrastructure state.

Normaldriftdetection
```
{normal_result}
```

Policycompliancedriftdetection
```
{policy_result}
```

Versionapileveldriftdetection:
```
{semantic_result}
```

Hiddenimplicitconfigdriftdetection
```
{hidden_result}
```

Behavioraldriftdetection
```
{behavioral_result}

```

Crossresourcedependencydriftdetection
```
{cross_result}
```

Semanticdriftdetection
```
{semantic_result}
```
Iac Configuration:
```
Find **ALL** IaC resources in the repository have detection from the Knowledge Base.  
**All IaC configurations are stored under the directory `iac_config/` in the KB.**
```
Desired State Description:
```
Find **ALL** corresponding AWS State resources have detection (where `status != deleted`).  
**All AWS Desired State configurations are stored under the directory `aws_state/` in the KB.**
```

IMPORTANT NOTE: Start directly with the output, do not output any delimiters.
IMPORTANT: Start with JSON output only.
Output JSON:
{{
  "remediation_type": "update_iac",
  "[type detection]"{{
      "remediation_suggestions": [{{ "resource_address": "...", "suggestion": "..." }}],
  }}
  "summary": "..."
}}

"""
}


results = {
    "normal_result": None,
    "policy_result": None,
    "semantic_result": None,
    "hidden_result": None,
    "behavioral_result": None,
    "cross_result": None,
    "version_result": None,
    "overlap_result": None
}
def extract_detection(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "normal":
                results["normal_result"] = v
            elif k == "policy":
                results["policy_result"] = v
            elif k == "semantic":
                results["semantic_result"] = v
            elif k == "hidden":
                results["hidden_result"] = v
            elif k == "behavioral":
                results["behavioral_result"] = v
            elif k == "cross":
                results["cross_result"] = v
            elif k == "version":
                results["version_result"] = v
            elif k == "overlap_result":
                results["overlap_result"] = v
            else:
                extract_detection(v)
    elif isinstance(obj, list):
        for item in obj:
            extract_detection(item)

def lambda_handler(event, context):
    print("event===================")
    print(event)
    print("==========================")
    extract_detection(event)
    print(results)
    detection_reports_json = json.dumps(event.get('detections', []))  # Từ Parallel Detection
    print(detection_reports_json)
    prompt = PROMPTS[REMEDIATION_TYPE].format(
        detection_reports_json=detection_reports_json,
        normal_result = results["normal_result"],
        policy_result = results["policy_result"],
        semantic_result = results["semantic_result"],
        hidden_result = results["hidden_result"],
        behavioral_result = results["behavioral_result"],
        cross_result = results["cross_result"],
        version_result = results["version_result"]
    )
    logger.info(f"Prompt for {REMEDIATION_TYPE}: {prompt}")
    
    agent_output = invoke_agent(prompt)
    
    parsed = extract_json_from_text(agent_output)
    if parsed:
        return parsed
    else:
        return {
            "remediation_type": REMEDIATION_TYPE,
            "remediation_suggestions": [],
            "summary": "No remediation needed"
        }

# === INVOKE AGENT ===
def invoke_agent(question: str):
    full_output = ""
    try:
        response = bedrock.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=str(int(time.time())),
            inputText=question
        )
        for event in response["completion"]:
            if "chunk" in event:
                full_output += event["chunk"]["bytes"].decode("utf-8")
    except Exception as e:
        logger.error(f"Agent invoke error: {str(e)}")
    return full_output

# === EXTRACT JSON ===
def extract_json_from_text(text: str):
    try:
        print("=== [TRACE] START extract_json_from_text ===")
        full_text = text.strip()
        print(f"[TRACE] Raw : {full_text}")

        # === B1: ƯU TIÊN TÌM JSON OBJECT { ... } ===
        start_obj = full_text.find('{')
        end_obj = full_text.rfind('}') + 1

        if start_obj != -1 and end_obj > start_obj:
            json_str = full_text[start_obj:end_obj]
            is_array = False
            print(f"[TRACE] Found JSON object: {len(json_str)} chars")
        else:
            # Nếu không có object, thử array
            start_arr = full_text.find('[')
            end_arr = full_text.rfind(']') + 1
            if start_arr != -1 and end_arr > start_arr:
                json_str = full_text[start_arr:end_arr]
                is_array = True
                print(f"[TRACE] Found JSON array: {len(json_str)} chars")
            else:
                print("[TRACE] No JSON found")
                return {}

        # === B2: Fix content bị cắt ===
        fixed = ""
        i = 0
        in_content = False

        while i < len(json_str):
            if not in_content and json_str[i:i+10] == '"content":':
                in_content = True
                fixed += json_str[i:i+10]
                i += 10
                quote = json_str.find('"', i)
                if quote == -1:
                    fixed += ' ""'
                    break
                fixed += json_str[i:quote+1]
                i = quote + 1
                continue

            if in_content and json_str[i] == '"' and json_str[i-1] != '\\':
                next_part = json_str[i+1:i+5]
                if any(x in next_part for x in [',', '}', '\n', '\r']):
                    in_content = False
            fixed += json_str[i]
            i += 1

        if in_content:
            fixed += '"INCOMPLETE"'

        json_str = fixed

        # === B3: Dọn phẩy thừa + đóng ngoặc ===
        json_str = re.sub(r',\s*([\]}])', r'\1', json_str)
        json_str = re.sub(r',\s*$', '', json_str)

        open_b = json_str.count('{')
        close_b = json_str.count('}')
        open_br = json_str.count('[')
        close_br = json_str.count(']')

        while open_b > close_b:
            json_str += '}'
            close_b += 1
        while open_br > close_br:
            json_str += ']'
            close_br += 1

        print(f"[TRACE] Final JSON: {json_str}")

        # === B4: Parse ===
        try:
            data = json.loads(json_str)
            return data
        except json.JSONDecodeError as e:
            print(f"[TRACE] JSON Error: {e}")
            print(f"[TRACE] JSON string:\n{json_str[:600]}")
            return {}  # Luôn trả object nếu là object

    except Exception as e:
        print(f"[TRACE] Exception: {e}")
        return {}
    finally:
        print("=== [TRACE] END extract_json_from_text ===")