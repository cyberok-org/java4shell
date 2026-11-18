# Vendor response and release status

Public-source review: **2026-11-18, approximately 01:45 UTC / 04:45 MSK**.
This is a dated snapshot, not a live feed or a complete vendor survey. Recheck the
linked sources before rollout. The [RCE product list](../README.md#disclosure-update--2026-11-18)
records Calif's exploitation report; the table below records remediation evidence.
Neither is a list of every affected product version.

## Verified advisory and development activity

| Product / supplier | Observed status | What operators can conclude |
| --- | --- | --- |
| OpenJDK / Oracle | **Official advisories published:** [OpenJDK](https://openjdk.org/groups/vulnerability/advisories/2026-11-17), [Oracle](https://www.oracle.com/security-alerts/cspunov2026.html) | The CVE is officially documented. Match the actual runtime distribution and build to supplier guidance; Oracle explicitly includes 8u511b33-perf, a separate lineage from community OpenJDK 8. |
| Elasticsearch | **Proposed runtime update:** [PR #166388](https://github.com/elastic/elasticsearch/pull/166388) is open and unmerged against `main`. It changes bundled OpenJDK from `27.0.1.0.3+1` to `27.0.1.1+4`. | The PR does not itself name this CVE; its relevance is inferred from the fixed JDK baseline. It is not evidence of a released Elasticsearch fix or a backport to supported branches. |
| Keycloak | **Proposed mitigation:** [PR #55294](https://github.com/keycloak/keycloak/pull/55294) is open and unmerged. It proposes `-XX:-UseBASE64Intrinsics` in startup scripts and the Operator container. | A contributor's proposal is not a shipped fix or an adopted vendor recommendation. Review the supported JVM-option mechanism and verify the effective setting after restart. |
| JFrog | **Guidance and scanner coverage published:** [JFrog Research](https://research.jfrog.com/post/java4shell-vulnerability/) lists fixed JDK baselines `17.0.21.1`, `21.0.13.1`, `25.0.5.1`, `27.0.1.1`, JVM mitigations, and Xray/Catalog coverage. | Scanner coverage is not product remediation. The article does not identify a fixed Artifactory release. |
| Artifactory self-managed | **New releases; CVE fix not verified:** [public release notes](https://docs.jfrog.com/releases/docs/artifactory-self-managed-releases) list `7.173.21` and `7.161.42` on November 17, with detailed notes behind MyJFrog/support. | Their dates alone do not establish that this CVE is fixed. Obtain the supported remediation and embedded-JDK details from JFrog, then verify the deployed runtime. |
| Red Hat | **Advisory and mitigation guidance:** [RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018) covers affected OpenJDK deployments and embedded/container runtimes. | Track package errata and container updates for the exact product. Use a supported update path; do not equate the bulletin with a verified fixed image for every product. |

The two PR states above were checked through GitHub's API; the Elasticsearch
version change was checked in its file diff. PR contents are proposals, and their
authors' testing claims are not our independently reproduced results.

## Other product release channels

The following checked pages did **not establish a specific shipped Java4Shell fix**
in this review. This is a limitation of the inspected public sources, not a claim
that vendors have taken no action or that no fix exists elsewhere.

| Product | Checked source and qualification |
| --- | --- |
| Jira / Confluence | The [November 17 security bulletin](https://confluence.atlassian.com/security/security-bulletin-november-17-2026-1874690748.html) does not name CVE-2026-114938. Do not treat its unrelated fixes as remediation for this JVM defect. |
| Jenkins | The [security advisory index](https://www.jenkins.io/security/advisories/) does not establish a dedicated fix. Verify the JVM in each controller/agent image or installation independently of the Jenkins core version. |
| PingFederate | The [13.1 release notes](https://docs.pingidentity.com/pingfederate/13.1/release_notes/pf_release_notes.html) do not establish a CVE-specific fixed build. Confirm the supported JVM update with the supplier. |
| Kafka | The [CVE list](https://kafka.apache.org/community/cve-list/) explicitly excludes dependency advisories. Its silence cannot clear the broker JVM. |
| Solr | The [security page](https://solr.apache.org/security.html) does not identify a fixed product/image for this CVE in the inspected content. Verify the actual deployment runtime. |
| Gerrit | The [3.14 release notes](https://www.gerritcodereview.com/3.14.html) do not establish this fix. A Gerrit application upgrade alone does not prove the JVM changed. |
| Spinnaker | The [release index](https://spinnaker.io/docs/releases/versions/) does not establish this fix. Check the JVMs in the individual deployed service images. |

## When to mark a deployment remediated

An open PR is a proposal. A merge establishes a source change, not release
availability. A mitigation excludes a code path but does not install the patch.
Mark a deployment patched only after matching a supplier-confirmed fixed runtime
or backport to the **running process**, including its container or bundled JDK,
and restarting/redeploying as required. Record a verified temporary mitigation
separately. See the [response guide](RESPONSE.md).

Until then, prioritize affected exposed deployments and reported RCE targets;
do not wait for a product-specific advisory or a visible JVM crash to act.
