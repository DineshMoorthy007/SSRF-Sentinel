class ParameterAnalyzer:

    PARAMETER_CATEGORIES = {

        "URL_INPUT": [
            "url",
            "uri",
            "target",
            "link",
            "src",
            "source"
        ],

        "REMOTE_RESOURCE": [
            "image",
            "file",
            "resource",
            "document",
            "download"
        ],

        "NETWORK_DESTINATION": [
            "proxy",
            "host",
            "endpoint",
            "server",
            "address"
        ],

        "CALLBACK": [
            "callback",
            "webhook",
            "notify",
            "return_url"
        ],

        "REDIRECTION": [
            "redirect",
            "next",
            "return",
            "continue",
            "destination"
        ]

    }

    PRIORITY = {

        "URL_INPUT": "HIGH",

        "REMOTE_RESOURCE": "HIGH",

        "NETWORK_DESTINATION": "HIGH",

        "CALLBACK": "HIGH",

        "REDIRECTION": "MEDIUM",

        "UNKNOWN": "LOW"

    }

    def __init__(self):

        self.analysis_results = []

    def classify_parameter(self, parameter):

        parameter = parameter.lower().strip()

        for category, parameters in self.PARAMETER_CATEGORIES.items():

            if parameter in parameters:

                return category

        return "UNKNOWN"

    def analyze(self, endpoints):

        print("\n[INFO] Starting parameter analysis...")

        self.analysis_results = []

        for endpoint in endpoints:

            parameters = endpoint.get(
                "parameters",
                []
            )

            for parameter in parameters:

                category = self.classify_parameter(
                    parameter
                )

                result = {

                    "endpoint": endpoint["path"],

                    "method": endpoint["method"],

                    "parameter": parameter,

                    "category": category,

                    "priority": self.PRIORITY[category],

                    "source": endpoint["source"],

                    "ssrf_candidate": category != "UNKNOWN"

                }

                self.analysis_results.append(result)

                print(
                    f"[+] Parameter: {parameter}"
                )

                print(
                    f"    Endpoint : {endpoint['path']}"
                )

                print(
                    f"    Category : {category}"
                )

                print(
                    f"    Priority : {result['priority']}"
                )

        print("\n[INFO] Parameter analysis completed.")

        return self.analysis_results

    def display_results(self):

        print("\n" + "=" * 65)

        print("             PARAMETER ANALYSIS RESULTS")

        print("=" * 65)

        if not self.analysis_results:

            print("[WARNING] No parameters identified.")

            return

        for result in self.analysis_results:

            print(
                f"\n[+] {result['parameter']}"
            )

            print(
                f"    Endpoint : {result['endpoint']}"
            )

            print(
                f"    Category : {result['category']}"
            )

            print(
                f"    Priority : {result['priority']}"
            )

            print(
                f"    SSRF Candidate : "
                f"{result['ssrf_candidate']}"
            )

        candidates = sum(
            1 for result in self.analysis_results
            if result["ssrf_candidate"]
        )

        print("\n" + "=" * 65)

        print(
            f"[SUCCESS] Total parameters: "
            f"{len(self.analysis_results)}"
        )

        print(
            f"[SUCCESS] Potential SSRF parameters: "
            f"{candidates}"
        )