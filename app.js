const API_URL = "http://127.0.0.1:8000";


async function scanWebsite() {

    const input =
        document.getElementById("urlInput");

    const url =
        input.value.trim();

    const error =
        document.getElementById("error");

    const loading =
        document.getElementById("loading");

    const results =
        document.getElementById("results");

    const button =
        document.getElementById("scanButton");


    error.textContent = "";

    if (!url) {

        error.textContent =
            "Digite uma URL para analisar.";

        return;
    }


    loading.classList.remove("hidden");

    results.classList.add("hidden");

    button.disabled = true;

    button.textContent = "SCAN...";


    try {

        const response =
            await fetch(
                `${API_URL}/scan`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


        const data =
            await response.json();


        if (!data.success) {

            throw new Error(
                data.error ||
                "Erro durante a análise."
            );
        }


        showResults(data);

    }

    catch (err) {

        error.textContent =
            err.message ||
            "Não foi possível conectar ao scanner.";

    }

    finally {

        loading.classList.add("hidden");

        button.disabled = false;

        button.textContent = "SCAN";
    }
}


function showResults(data) {

    const results =
        document.getElementById("results");

    const status =
        document.getElementById("overallStatus");

    const scannedUrl =
        document.getElementById("scannedUrl");


    scannedUrl.textContent =
        data.url;


    status.className =
        `overall ${data.summary.overall}`;


    status.textContent =
        data.summary.overall.toUpperCase();


    document.getElementById(
        "cleanCount"
    ).textContent =
        data.summary.clean;


    document.getElementById(
        "warningCount"
    ).textContent =
        data.summary.warnings;


    document.getElementById(
        "dangerCount"
    ).textContent =
        data.summary.danger;


    document.getElementById(
        "totalCount"
    ).textContent =
        data.summary.total;


    const list =
        document.getElementById("engineList");


    list.innerHTML = "";


    data.results.forEach(result => {

        const item =
            document.createElement("div");

        item.className =
            "engine";


        const left =
            document.createElement("div");


        const name =
            document.createElement("div");

        name.className =
            "engine-name";

        name.textContent =
            result.name;


        const message =
            document.createElement("div");

        message.className =
            "engine-message";

        message.textContent =
            result.message;

        left.appendChild(name);
        left.appendChild(message);

        if (result.name === "VirusTotal" && Array.isArray(result.antivirus)) {
            const antivirusList = document.createElement("ul");
            antivirusList.className = "antivirus-list";

            result.antivirus.forEach(item => {
                const antivirusItem = document.createElement("li");
                antivirusItem.className = "antivirus-item";
                antivirusItem.textContent = `${item.engine}: ${item.result || "unknown"}`;
                antivirusList.appendChild(antivirusItem);
            });

            left.appendChild(antivirusList);
        }


        const badge =
            document.createElement("div");

        badge.className =
            `engine-status status-${result.status}`;


        if (result.status === "clean") {
            badge.textContent = "CLEAN";
        }

        else if (
            result.status === "warning"
        ) {
            badge.textContent = "WARNING";
        }

        else {
            badge.textContent = "DETECTED";
        }


        item.appendChild(left);

        item.appendChild(badge);

        list.appendChild(item);
    });


    const details =
        document.getElementById("details");

    const detailsContent =
        document.getElementById("detailsContent");


    detailsContent.textContent =
        JSON.stringify(
            data,
            null,
            2
        );


    details.classList.remove("hidden");

    results.classList.remove("hidden");


    results.scrollIntoView({
        behavior: "smooth"
    });
}


document
    .getElementById("urlInput")
    .addEventListener(
        "keydown",
        function(event) {

            if (event.key === "Enter") {
                scanWebsite();
            }

        }
    );
