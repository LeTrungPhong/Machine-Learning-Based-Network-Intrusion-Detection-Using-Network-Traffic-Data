Findings text inserted into eda/data_analysis.ipynb by scripts/build_eda_notebook.py.
Each section starts with "@@ <key>". Written after reading the executed outputs; re-check
the numbers if the cleaning or sampling changes.

@@ dims
The 8 raw CSVs hold 2,830,743 flows. After cleaning, 2,498,103 rows and 81 columns remain:
68 numeric features (float32), the categorical inputs `dst_port` and `protocol`, the flow
identifiers, a UTC timestamp, `day`, and three label columns. Wednesday (692,703 raw rows) and
Monday (529,918) are the largest files.

@@ quality
Missing values are rare and limited to rate features: `Flow Bytes/s` has 1,358 NaN and 1,509
infinite values, and `Flow Packets/s` has 2,867 infinite values (both rates are undefined when
the duration is 0). Negative values fall into two groups:

* `Init_Win_bytes_backward` (1,441,552 rows) and `Init_Win_bytes_forward` (1,001,189) are -1.
  This is a sentinel for "no TCP packet in that direction", so it was kept.
* Small numbers of impossible negatives: `Flow IAT Min` (2,891), `Flow Duration` and the Flow
  IAT Mean/Max (115 each), and header lengths (22-35). These were set to NaN and are imputed
  with training-set medians.

11.70% of rows (331,202) are exact duplicates of an earlier row. Another 7,144 rows are
*conflicting* duplicates: identical features with different labels, mostly DoS Hulk (5,317),
PortScan (1,053) and BENIGN (766). Their labels cannot be learned from the features, so they
were removed. 8 bulk/flag features are constant over the whole dataset and were dropped.

@@ labels
The data is strongly imbalanced. BENIGN is 82.98% of cleaned flows and attacks are 17.02%.
The largest-to-smallest class ratio is 188,451 : 1 (BENIGN vs Heartbleed with 11 flows).
Infiltration (36) and Web Attack - Sql Injection (21) are similarly tiny. Deduplication hits
some classes much harder than others:

* PortScan loses 43.2% of its rows and SSH-Patator 45.4%. Many probe and login flows are
  byte-identical.
* DDoS, Web Attack - XSS, Infiltration and Heartbleed lose nothing.

Per-class metrics for the three smallest classes rest on 2-7 test flows each (see the split
report), so they cannot be estimated reliably.

@@ attacks
Every attack type occurs on a single day only:

* Tuesday: FTP/SSH-Patator
* Wednesday: all DoS variants and Heartbleed
* Thursday: Web attacks and Infiltration
* Friday: Bot, PortScan and DDoS

Monday is purely BENIGN. Attack share per day ranges from 0% (Monday) and 0.55% (Thursday)
to 32.6% (Wednesday) and 37.2% (Friday). Two consequences follow:

* A day-based split puts entirely different attack types in train and test. This is the right
  setup for evaluating unseen attacks, but a multi-class model cannot learn the test classes.
* A random split mixes flows from the same attack burst into train and test, which inflates
  scores.

@@ distributions
The two classes differ strongly in timing and size:

* **PortScan** flows are almost instantaneous: median duration 50 us, 99.4% shorter than 1 ms.
  BENIGN has a median of 46,323 us, and 34.5% of BENIGN flows are under 1 ms.
* **Slow DoS** (slowloris median 99,999,408 us, Slowhttptest 63,120,444 us), **DoS Hulk**
  (86,680,684 us) and **Heartbleed** flows sit near the 120 s flow-timeout ceiling.
* **Packet size:** median average packet size is 0 bytes for DoS Slowhttptest and Web Attack
  Brute Force/XSS and 3 bytes for PortScan. BENIGN is 79 bytes. DoS Hulk (918), DDoS (898) and
  Heartbleed (1,620) are much larger.

These attack-specific modes are visible as separate peaks in the duration histogram. Note that
the "Attack" curve is a label-capped mix, so its shape is not weighted by attack prevalence.

@@ correlation
The feature set is highly redundant. On the label-capped sample, 118 feature pairs have
|r| > 0.9, 63 have |r| > 0.95 and 28 have |r| > 0.99.

* Several pairs are exact copies (r = 1.0000): every `subflow_*` column equals its `total_*`
  counterpart, and `avg_fwd/bwd_segment_size` equals `fwd/bwd_packet_length_mean`.
* Some exact copies are between unrelated flags. `fwd_psh_flags` equals `syn_flag_count`,
  `rst_flag_count` equals `ece_flag_count`, and `fwd_urg_flags` equals `cwe_flag_count`. This
  points to mislabelled flag columns in the published CSVs. It agrees with STEP 4, where CIC
  reported SYN = 0 for flows whose packets clearly contained a SYN.

The preprocessing pipeline removes one feature from each |r| > 0.99 pair, using correlations
computed on the training split only. That drops 21 features for `temporal_per_class`.

@@ outliers
By the 1.5 x IQR rule, BENIGN traffic is very heavy-tailed: the median feature has 17.1%
of BENIGN flows outside the fences, with timing and length-variability features highest
(e.g. `bwd_packet_length_std` 24.1%, `flow_iat_std` 23.6%, `flow_duration` 23.3%).

Within the attack sample the share is only 3.0%, because each attack tool produces very uniform
flows. Outliers are therefore normal traffic diversity, not errors, and are not removed. The
pipeline uses a signed log1p transform plus RobustScaler instead.

@@ comparison
Median feature values separate several attack families clearly:

* PortScan: 1 forward packet, 0 payload bytes.
* DoS Slowhttptest and Web Attack Brute Force/XSS: 0 forward payload bytes.
* Heartbleed: 2,792 forward packets and 12,264 bytes in one flow.
* Bot and DDoS: short forward payloads of 6 and 26 bytes.

`init_win_bytes_backward` is a warning sign. Its median is 28,960 for both Web Attack Brute
Force and XSS, and -1 for BENIGN, because the value reflects the TCP stack of the specific
victim server. Destination ports are similarly concentrated:

* DoS, DDoS and Web Attacks: port 80
* Bot: mostly 8080 (1,248 of 1,953)
* Patator: ports 21/22
* Heartbleed and Infiltration: port 444

Port and window features will help on this dataset but may not transfer to other networks.
STEP 10 evaluates this with ablation experiments.

@@ importance
On 102,216 label-capped rows from the temporal training split, the Random Forest ranks
`init_win_bytes_backward` first (0.0646), well ahead of the next features: `min_seg_size_forward`
0.0322, `avg_bwd_segment_size` 0.0304 and `fwd_packet_length_max` 0.0293. Importance is spread
across size, rate and timing features after that.

The top feature is the testbed-specific TCP window size noted above, which reinforces the need
for the ablation study. Because correlated features split importance between them, this ranking
is exploratory only.

@@ summary
* Cleaned data: 2,498,103 flows, 68 numeric + 2 categorical features, 15 labels in 8 families.
* Data problems handled without using test data:
  * 11.7% exact duplicates and 7,144 label-conflicting rows removed;
  * Inf/NaN/impossible negatives set to NaN and imputed with training medians;
  * 8 constant and 21 near-duplicate (|r| > 0.99) features dropped.
* The imbalance is extreme (188,451 : 1). The three rarest classes have 2-7 test flows, so their
  per-class metrics cannot be estimated reliably. Use class weights or SMOTE on the training
  split, and report macro-F1.
* Attacks are confined to single days, so:
  * multi-class classification uses a temporal per-class split (train on earlier flows, test on
    later ones);
  * unseen-attack evaluation uses a day split (train Mon-Wed, test Thu-Fri).
* Some highly discriminative features (`init_win_bytes_backward`, destination port) reflect the
  testbed configuration and need ablation before any claim of generalisation.
