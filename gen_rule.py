import json
from tqdm import tqdm
from androguard.misc import AnalyzeAPK


def rule_generate(apis):
    rules = list()
    
    for api_1 in apis:
        for api_2 in apis:
            
            if api_1.class_name == api_2.class_name and \
               api_1.name == api_2.name and \
               api_1.descriptor == api_2.descriptor:
                   continue
               
            rule = {
                "crime": "",
                "permission": [],
                "api": [
                    {
                        "class": str(api_1.class_name),
                        "method": str(api_1.name),
                        "descriptor": str(api_1.descriptor),
                    },
                    {
                        "class": str(api_2.class_name),
                        "method": str(api_2.name),
                        "descriptor": str(api_2.descriptor),
                    }
                ],
                "score": 1,
                "label": []
            }
            rules.append(rule)
            
    return rules

def android_apis(analysis):
    apis = set()
    
    for external_cls in analysis.get_external_classes():
        for meth_analysis in external_cls.get_methods():
            if meth_analysis.is_android_api():
                apis.add(meth_analysis)
    
    return apis

APK_PATH = "samples/Ahmyth.apk"

_, _, analysis = AnalyzeAPK(APK_PATH)

apis_set = android_apis(analysis)
rules_list = rule_generate(apis_set)
rule_filename = 0

for rule in tqdm(rules_list):
    
    rule_filename += 1 
    
    # rule_file = open(f"output_rules/{rule_filename}.json", "w")
    # json.dump(rule, rule_file, indent=4)
    # rule_file.close()