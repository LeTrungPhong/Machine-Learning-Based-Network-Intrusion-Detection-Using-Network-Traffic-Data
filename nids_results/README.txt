HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG (NIDS) – KẾT QUẢ
Thời điểm đóng gói: 2026-11-21 19:11:00
Dataset: UNSW-NB15, CIC-IDS2017
Mô hình: RandomForest, CNN-BiLSTM | Bài toán: binary, multi
Cấu hình: {"DATASETS": ["UNSW-NB15", "CIC-IDS2017"], "UNSW_PREFERRED_DIR": "unsw-nb15-eda", "CIC_PREFERRED_DIR": "MachineLearningCVE", "CIC_SAMPLE_FRAC": 0.5, "CIC_MIN_PER_CLASS": 5000, "EDA_SAMPLE": 200000, "CORR_THRESHOLD": 0.95, "MIN_CAT_FREQ": 0.005, "MAX_CATS": 20, "VAL_SIZE": 0.15, "RF_TUNE": true, "RF_TUNE_SUBSET": 40000, "RF_TUNE_ITER": 8, "DL_EPOCHS": 30, "DL_BATCH": 1024, "DL_PATIENCE": 5, "RUN_SHAP": true, "SHAP_SAMPLES": 200, "SHAP_TREES": 25}

Cấu trúc thư mục:
  figures/ : biểu đồ EDA, confusion matrix, ROC/PR, learning curve, so sánh (.png)
  results/ : summary_metrics.csv, per_class_f1_*.csv, mcnemar.csv, dl_histories.json, config_and_cleaning_log.json
  models/  : rf_*.joblib (Random Forest), dl_*.keras (CNN-BiLSTM), preprocessor_*.joblib, label_encoder_*.joblib
  (Load preprocessor_*.joblib cần định nghĩa lại class NIDSPreprocessor ở mục 4.3 của notebook)

BẢNG TỔNG HỢP METRIC TRÊN TEST SET:
       Model     Dataset   Task  Accuracy  Precision_macro  Recall_macro  F1_macro  F1_weighted  ROC_AUC  PR_AUC     DR    FAR    FNR  Train_time_s  Infer_ms_per_1000  Size_MB
  CNN-BiLSTM CIC-IDS2017 binary    0.9985           0.9968        0.9981    0.9974       0.9985   1.0000  0.9998 0.9975 0.0012 0.0025      549.3036             9.1134   1.6817
RandomForest CIC-IDS2017 binary    0.9989           0.9977        0.9984    0.9981       0.9989   0.9999  0.9997 0.9976 0.0008 0.0024      223.5635             6.8908  51.5844
  CNN-BiLSTM CIC-IDS2017  multi    0.9977           0.9544        0.9914    0.9694       0.9978   1.0000  0.9835 0.9989 0.0025 0.0011      359.6600             8.4863   1.6935
RandomForest CIC-IDS2017  multi    0.9988           0.9825        0.9839    0.9832       0.9988   1.0000  0.9943 0.9970 0.0008 0.0030      460.9193             7.3758  68.9642
  CNN-BiLSTM   UNSW-NB15 binary    0.8297           0.8373        0.8546    0.8284       0.8318   0.9645  0.9511 0.9639 0.2547 0.0361       61.5165            16.4419   1.6817
RandomForest   UNSW-NB15 binary    0.8310           0.8416        0.8582    0.8300       0.8330   0.9699  0.9583 0.9775 0.2612 0.0225       26.8555             5.1005  49.8978
  CNN-BiLSTM   UNSW-NB15  multi    0.6824           0.4785        0.6449    0.4895       0.7319   0.9590  0.5387 0.9835 0.3366 0.0165       67.7234            16.4492   1.6950
RandomForest   UNSW-NB15  multi    0.6772           0.5650        0.6625    0.5500       0.7276   0.9554  0.5903 0.9896 0.3694 0.0104       44.2880             8.0691 248.2807
