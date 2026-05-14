const analyzeBtn = document.getElementById("analyzeBtn");

const urlInput = document.getElementById("urlInput");

const resultBox = document.getElementById("result");

// ===============================
// ANALYZE BUTTON
// ===============================

analyzeBtn.addEventListener("click", async () => {

    const url = urlInput.value.trim();

    // EMPTY CHECK

    if (!url) {

        resultBox.innerHTML = `
            <h2 style="color:red;">
                PLEASE ENTER A URL
            </h2>
        `;

        return;
    }

    // LOADING

    resultBox.innerHTML = `
        <h2 style="color:orange;">
            ANALYZING URL...
        </h2>
    `;

    try {

        // ===============================
        // API REQUEST
        // ===============================

        const response = await fetch("/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });

        // ===============================
        // JSON RESPONSE
        // ===============================

        const data = await response.json();

        console.log(data);

        // ===============================
        // ERROR HANDLING
        // ===============================

        if (data.status === "error") {

            resultBox.innerHTML = `
                <h2 style="color:red;">
                    ERROR OCCURRED
                </h2>

                <p>
                    ${data.message}
                </p>
            `;

            return;
        }

        // ===============================
        // COLORS
        // ===============================

        let color = "#00ff99";

        if (data.risk === "HIGH") {

            color = "#ff0000";

        } else if (data.risk === "MEDIUM") {

            color = "#ffae00";
        }

        // ===============================
        // REASONS HTML
        // ===============================

        let reasonsHTML = "";

        data.reasons.forEach(reason => {

            reasonsHTML += `
                <li>${reason}</li>
            `;
        });

        // ===============================
        // PREVENTION HTML
        // ===============================

        let preventionHTML = "";

        data.prevention.forEach(item => {

            preventionHTML += `
                <li>${item}</li>
            `;
        });

        // ===============================
        // FINAL RESULT
        // ===============================

        resultBox.innerHTML = `

            <div class="result-content">

                <h2 style="color:${color};">
                    ${data.status}
                </h2>

                <p>
                    <strong>URL:</strong>
                    ${data.url}
                </p>

                <p>
                    <strong>Threat Level:</strong>
                    ${data.risk}
                </p>

                <p>
                    <strong>Phishing Score:</strong>
                    ${data.score}%
                </p>

                <p>
                    <strong>Timestamp:</strong>
                    ${data.timestamp}
                </p>

                <hr>

                <h3>
                    Detection Reasons
                </h3>

                <ul>
                    ${reasonsHTML}
                </ul>

                <hr>

                <h3>
                    Prevention Tips
                </h3>

                <ul>
                    ${preventionHTML}
                </ul>

            </div>

        `;

    } catch (error) {

        console.error(error);

        resultBox.innerHTML = `

            <h2 style="color:red;">
                SERVER ERROR
            </h2>

            <p>
                Backend connection failed.
            </p>

        `;
    }

});

// ===============================
// ENTER KEY SUPPORT
// ===============================

urlInput.addEventListener("keypress", function(event) {

    if (event.key === "Enter") {

        analyzeBtn.click();
    }

});