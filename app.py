import streamlit as st
import pandas as pd
from dotenv import load_dotenv

from ml_engine import predict_url
from message_analyzer import analyze_message
from ai_explainer import generate_explanation
from history import load_history, save_investigation, clear_history
from reporting import generate_pdf_report

load_dotenv()

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ PhishGuard AI")
st.subheader("Intelligent Phishing Investigation and Prevention Assistant")

st.info(
    "Analyze suspicious URLs and messages, review warning signs, "
    "and generate a PDF investigation report. Results are not a guarantee "
    "that a website or message is safe."
)

if "latest" not in st.session_state:
    st.session_state.latest = None

investigate_tab, history_tab, about_tab = st.tabs(
    ["🔎 Investigate", "📋 History", "ℹ️ About"]
)

with investigate_tab:
    st.header("Investigate a URL or message")

    with st.form("analysis_form"):
        url_input = st.text_input(
            "Suspicious URL (optional)",
            placeholder="https://example.com/login",
        )
        message_input = st.text_area(
            "Suspicious email or message (optional)",
            placeholder="Paste the suspicious message here...",
            height=150,
        )
        submitted = st.form_submit_button(
            "Analyze now",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        if not url_input.strip() and not message_input.strip():
            st.warning("Enter a URL, a message, or both.")
        else:
            with st.spinner("Analyzing..."):
                message_result = (
                    analyze_message(message_input.strip())
                    if message_input.strip()
                    else None
                )

                selected_url = url_input.strip()

                if (
                    not selected_url
                    and message_result
                    and message_result.get("urls")
                ):
                    selected_url = message_result["urls"][0]

                url_result = (
                    predict_url(selected_url)
                    if selected_url
                    else None
                )

                explanation = generate_explanation(
                    url_result=url_result,
                    message_result=message_result,
                )

                prediction = (
                    url_result.get("prediction", "Unavailable")
                    if url_result
                    else "Message-only analysis"
                )

                score = (
                    url_result.get("phishing_score")
                    if url_result and url_result.get("status") == "success"
                    else None
                )

                indicators = (
                    len(message_result.get("indicators", []))
                    if message_result
                    else 0
                )

                save_investigation(
                    url=selected_url,
                    prediction=prediction,
                    phishing_score=score,
                    message_indicator_count=indicators,
                    message=message_input.strip(),
                )

                st.session_state.latest = {
                    "url_result": url_result,
                    "message_result": message_result,
                    "explanation": explanation,
                }

    result = st.session_state.latest

    if result:
        st.divider()
        st.header("Investigation results")

        url_result = result["url_result"]
        message_result = result["message_result"]
        explanation = result["explanation"]

        if url_result:
            st.subheader("URL analysis")

            if url_result.get("status") == "success":
                col1, col2 = st.columns(2)

                with col1:
                    st.metric(
                        "Model prediction",
                        url_result.get("prediction", "Unknown"),
                    )

                with col2:
                    score = url_result.get("phishing_score")
                    st.metric(
                        "Estimated phishing probability",
                        f"{score:.1%}"
                        if isinstance(score, (int, float))
                        else "Unavailable",
                    )

                if url_result.get("is_phishing"):
                    st.error(
                        "Potential phishing detected. Verify the URL "
                        "before interacting with it."
                    )
                else:
                    st.success(
                        "The model classified this URL as potentially "
                        "legitimate. This does not prove it is safe."
                    )

                with st.expander("View extracted URL features"):
                    st.dataframe(
                        pd.DataFrame(
                            list(url_result.get("features", {}).items()),
                            columns=["Feature", "Value"],
                        ),
                        use_container_width=True,
                        hide_index=True,
                    )
            else:
                st.warning(
                    url_result.get(
                        "message",
                        "URL analysis could not be completed.",
                    )
                )

        if message_result:
            st.subheader("Message analysis")
            st.write(
                message_result.get(
                    "summary",
                    "Message analysis completed.",
                )
            )

            urls = message_result.get("urls", [])
            if urls:
                st.write("URLs found:")
                for found_url in urls:
                    st.code(found_url)

            indicators = message_result.get("indicators", [])
            if indicators:
                st.write("Potential warning signs:")
                for indicator in indicators:
                    evidence = ", ".join(
                        str(item)
                        for item in indicator.get("evidence", [])
                    )
                    st.markdown(
                        f"- **{indicator.get('type', 'Indicator')}:** "
                        f"{evidence or 'Review required'}"
                    )
            else:
                st.info("No configured warning indicators were found.")

        st.subheader("🤖 Investigation explanation")
        st.write(explanation)

        pdf_bytes = generate_pdf_report(
            url_result=url_result,
            message_result=message_result,
            explanation=explanation,
        )

        st.download_button(
            "📄 Download PDF report",
            data=pdf_bytes,
            file_name="PhishGuard_AI_Report.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

with history_tab:
    st.header("Investigation history")
    history = load_history()

    if history:
        history_df = pd.DataFrame(history)

        if "phishing_score" in history_df.columns:
            history_df["phishing_score"] = history_df[
                "phishing_score"
            ].apply(
                lambda value: (
                    f"{value:.1%}"
                    if isinstance(value, (int, float))
                    else "Unavailable"
                )
            )

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

        confirm_clear = st.checkbox(
            "I confirm that I want to delete the saved history."
        )

        if st.button("Clear history"):
            if confirm_clear:
                clear_history()
                st.session_state.latest = None
                st.success("History cleared.")
                st.rerun()
            else:
                st.warning("Please confirm before clearing history.")
    else:
        st.info("No investigations saved yet.")

with about_tab:
    st.header("About PhishGuard AI")
    st.markdown(
        """
        **PhishGuard AI** combines machine learning and rule-based analysis
        to help investigate potentially suspicious URLs and messages.

        **Features**
        - URL classification using a trained model
        - URL feature extraction
        - Suspicious message indicators
        - AI-assisted explanations with a local fallback
        - Investigation history
        - Downloadable PDF reports

        **Limitations**
        - The model analyzes URL characteristics, not the live webpage.
        - Warning indicators can produce false positives or miss threats.
        - HTTPS does not guarantee a website is trustworthy.
        - Predictions should be treated as preliminary evidence.

        Never enter passwords, OTPs, or payment details through links
        in unsolicited messages. Verify requests through official channels.
        """
    )

st.divider()
st.caption("PhishGuard AI | Cybersecurity awareness project")
