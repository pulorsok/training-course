from androguard.misc import AnalyzeAPK

def android_apis(analysis):
    apis = set()
    
    for external_cls in analysis.get_external_classes():
        for meth_analysis in external_cls.get_methods():
            if meth_analysis.is_android_api():
                apis.add(meth_analysis)
    
    return apis

APK_PATH = "Ahmyth.apk"

_, _, analysis = AnalyzeAPK(APK_PATH)

apis_set = android_apis(analysis)

for api in apis_set:
    print(f"{str(api.class_name)} -> {str(api.name)} {str(api.descriptor)}")
    