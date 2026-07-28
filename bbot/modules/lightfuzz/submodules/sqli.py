from .base import BaseLightfuzz
from bbot.errors import HttpCompareError


class sqli(BaseLightfuzz):
    """
    Detects SQL injection vulnerabilities.

    Techniques:

    * Error-based Detection:
       - Injects single quotes and observes error responses
       - Tests quote escape sequence variations
       - Matches against known SQL error patterns

    * Time-based Blind Detection:
       - Uses vendor-specific time delay payloads
       - Confirms delays with statistical analysis
       - Requires multiple confirmations to eliminate false positives
    """

    friendly_name = "SQL Injection"

    delay_low = 3
    delay_high = 8
    delay_margin = 1.5
    delay_scale_margin = 1.75
    delay_stage1_reps = 3
    delay_stage2_reps = 3

    # These are common error strings that strongly indicate SQL injection
    sqli_error_strings = [
        "Unterminated string literal",
        "Failed to parse string literal",
        "error in your SQL syntax",
        "syntax error at or near",
        "Unknown column",
        "unterminated quoted string",
        "Unclosed quotation mark",
        "Incorrect syntax near",
        "SQL command not properly ended",
        "string not properly terminated",
    ]

    DELAY_PROBE_TEMPLATES = [
        "'||pg_sleep({d})--",
        "' OR (SELECT TRUE FROM pg_sleep({d})) LIMIT 1-- -",
        "1' AND (SLEEP({d})) AND '",
        "' OR SLEEP({d}) IS NOT NULL LIMIT 1-- -",
        " OR SLEEP({d}) IS NOT NULL LIMIT 1-- -",
        "' AND (SELECT 1 FROM DUAL WHERE DBMS_LOCK.SLEEP({d})=0) AND '1'='1",
        "'; WAITFOR DELAY '00:00:{d:02d}'--",
        "; WAITFOR DELAY '00:00:{d:02d}'--",
    ]

    async def fuzz(self):
        cookies = self.event.data.get("assigned_cookies", {})
        probe_value = self.incoming_probe_value(populate_empty=True)
        http_compare = self.compare_baseline(
            self.event.data["type"], probe_value, cookies, additional_params_populate_empty=True
        )

        try:
            # send the with a single quote, and then another with two single quotes
            single_quote = await self.compare_probe(
                http_compare,
                self.event.data["type"],
                f"{probe_value}'",
                cookies,
                additional_params_populate_empty=True,
            )
            double_single_quote = await self.compare_probe(
                http_compare,
                self.event.data["type"],
                f"{probe_value}''",
                cookies,
                additional_params_populate_empty=True,
            )
            # if the single quote probe response is different from the baseline
            if single_quote[0] is False:
                # check for common SQL error strings in the response
                for sqli_error_string in self.sqli_error_strings:
                    if sqli_error_string.lower() in single_quote[3].text.lower():
                        self.results.append(
                            {
                                "type": "FINDING",
                                "description": (
                                    f"Possible SQL injection. {self.metadata()} Detection Method: [SQL Error Detection] Detected String: [{sqli_error_string}]. "
                                    "The application returned a database error after SQL syntax was injected into the parameter. If confirmed, an attacker may be able to read or modify database data and bypass application authorization checks. "
                                    "SQL injection occurs when user input is treated as part of a database query instead of as plain data. "
                                    "Error messages are useful evidence because they show the database parser reacted to the injected syntax. "
                                    "The affected query should use parameterized statements or a safe ORM, avoid string concatenation, and return generic errors that do not expose database internals."
                                ),
                            }
                        )
                        break
            # if both probes were successful (and had a response)
            if single_quote[3] and double_single_quote[3]:
                # Ensure none of the status codes are "429"
                if (
                    single_quote[3].status_code != 429
                    and double_single_quote[3].status_code != 429
                    and http_compare.baseline.status_code != 429
                    and http_compare.baseline.status_code != 403  # Ensure the baseline status code is not 403
                ):  # prevent false positives from rate limiting
                    # if the code changed in the single quote probe, and the code is NOT the same between that and the double single quote probe, SQL injection is indicated
                    if "code" in single_quote[1] and (
                        single_quote[3].status_code != double_single_quote[3].status_code
                    ):
                        self.results.append(
                            {
                                "type": "FINDING",
                                "description": (
                                    f"Possible SQL injection. {self.metadata()} Detection Method: [Single Quote/Two Single Quote, Code Change ({http_compare.baseline.status_code}->{single_quote[3].status_code}->{double_single_quote[3].status_code})]. "
                                    "The application responded differently to SQL quote probes, which suggests input may be interpreted inside a database query. If confirmed, attackers may be able to extract, modify, or delete database records. "
                                    "For a non-specialist, the single quote is a common way to test whether input can break out of a text value inside SQL. A different response after quote changes can indicate the database is seeing attacker-supplied syntax. "
                                    "Validate this carefully, then fix the query with parameterized statements, strict input handling, and least-privilege database accounts."
                                ),
                            }
                        )
            else:
                self.debug("Failed to get responses for both single_quote and double_single_quote")
        except HttpCompareError as e:
            self.verbose(f"Encountered HttpCompareError Sending Compare Probe: {e}")

        baseline_1 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )
        baseline_2 = await self.standard_probe(
            self.event.data["type"], cookies, probe_value, additional_params_populate_empty=True
        )

        if baseline_1 and baseline_2:
            baseline_1_delay = baseline_1.elapsed.total_seconds()
            baseline_2_delay = baseline_2.elapsed.total_seconds()
            base_floor = min(baseline_1_delay, baseline_2_delay)

            junk_value = f"{probe_value}{self.lightfuzz.helpers.rand_string(20, numeric_only=True)}"
            junk_response = await self.standard_probe(
                self.event.data["type"], cookies, junk_value, additional_params_populate_empty=True
            )
            if junk_response:
                junk_delta = junk_response.elapsed.total_seconds() - base_floor
                if any(abs(junk_delta - k * self.delay_low) <= self.delay_margin for k in (1, 2)):
                    self.debug("Junk control probe matched delay window, aborting time-based tests")
                    return

            for template in self.DELAY_PROBE_TEMPLATES:
                low_times = []
                stage1_failed = False
                payload_low = template.format(d=self.delay_low)
                for _ in range(self.delay_stage1_reps):
                    r = await self.standard_probe(
                        self.event.data["type"],
                        cookies,
                        f"{probe_value}{payload_low}",
                        additional_params_populate_empty=True,
                        timeout=20,
                    )
                    if not r:
                        self.debug("Stage 1 delay probe request failed")
                        stage1_failed = True
                        break
                    if r.status_code == 403:
                        self.debug("Stage 1 probe returned 403, skipping template")
                        stage1_failed = True
                        break
                    low_times.append(r.elapsed.total_seconds())

                if stage1_failed or not low_times:
                    continue

                f_low = min(low_times)
                d_low = f_low - base_floor
                k = None
                for candidate_k in (1, 2):
                    if abs(d_low - candidate_k * self.delay_low) <= self.delay_margin:
                        k = candidate_k
                        break

                if k is None:
                    self.debug(f"Stage 1 rejected: d_low={d_low:.2f}s does not match delay_low={self.delay_low}s")
                    continue

                self.verbose(
                    f"Stage 1 passed {self.event.data['url']}: d_low={d_low:.2f}s, k={k}, proceeding to Stage 2"
                )

                high_times = []
                stage2_failed = False
                payload_high = template.format(d=self.delay_high)
                for _ in range(self.delay_stage2_reps):
                    r = await self.standard_probe(
                        self.event.data["type"],
                        cookies,
                        f"{probe_value}{payload_high}",
                        additional_params_populate_empty=True,
                        timeout=30,
                    )
                    if not r:
                        self.debug("Stage 2 delay probe request failed")
                        stage2_failed = True
                        break
                    if r.status_code == 403:
                        self.debug("Stage 2 probe returned 403, skipping template")
                        stage2_failed = True
                        break
                    high_times.append(r.elapsed.total_seconds())

                if stage2_failed or not high_times:
                    continue

                f_high = min(high_times)
                d_high = f_high - base_floor
                absolute_ok = abs(d_high - k * self.delay_high) <= self.delay_margin
                scaling_ok = abs((f_high - f_low) - k * (self.delay_high - self.delay_low)) <= self.delay_scale_margin

                if absolute_ok and scaling_ok:
                    self.results.append(
                        {
                            "type": "FINDING",
                            "description": (
                                f"Possible Blind SQL Injection. {self.metadata()} "
                                f"Detection Method: [Scaling Delay Probe "
                                f"(k={k}, {self.delay_low}s->{d_low:.1f}s, {self.delay_high}s->{d_high:.1f}s)] "
                                f"Payload: [{payload_high}]. "
                                "The response timing changed after a database delay payload, suggesting the parameter may influence SQL execution even when errors are not visible. If confirmed, attackers can extract data through timing or boolean inference. "
                                "Blind SQL injection is harder to see because the page may not print database errors or data directly; instead, the attacker asks yes-or-no questions and observes delays or response differences. "
                                "The affected code should be reviewed for dynamic SQL, fixed with parameterized queries, and tested to confirm the delay payload no longer changes server behavior."
                            ),
                        }
                    )
                else:
                    self.verbose(
                        f"Stage 2 rejected {self.event.data['url']}: d_high={d_high:.2f}s, "
                        f"absolute_ok={absolute_ok}, scaling_ok={scaling_ok}"
                    )

        else:
            self.debug("Could not get baseline for time-delay tests")
