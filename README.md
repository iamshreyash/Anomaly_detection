# Anomaly detection with isolation forest.

## Tools & Libraries: 

### Programming Language : Python v3.8

- **pandas:** Data manipulation
- **sklearn.preprocessing.StandardScaler:** Normalizing numerical features.

- **sklearn.ensemble.IsolationForest:** Training the Isolation Forest model.

- **pickle:** Saving and loading scaler and threshold artifacts.
- **Joblib:** Saving one-hot encoded column names.
- **glob:** Finding CSV files (capture_*.csv).
- **Tkineter:** Designing GUI and displaying  
- **Threading:** Threading the processes

  ### Model Training :

- In this project, we employ Isolation Forest, an unsupervised anomaly detection algorithm that isolates anomalies by constructing random decision trees. The algorithm is particularly efficient for large datasets like ours.
Applied to our dataset with 2,491,772 rows and 13 features , It builds 100 random trees (n_estimators=100), where each tree randomly selects a feature (e.g., ttl, time_diff) and a split value (e.g., ttl < 64) to partition the data. Anomalous data points (benign outliers) are isolated more quickly, resulting in shorter path lengths through the trees.
