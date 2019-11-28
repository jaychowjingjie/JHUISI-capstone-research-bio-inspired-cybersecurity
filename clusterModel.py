import numpy as np
import pandas as pd
from sklearn.datasets import load_digits
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans
from sklearn.metrics import accuracy_score
import pickle

pd.options.mode.chained_assignment = None

data = pd.read_csv('full2.csv')
Y = data['class']
data = data.drop(columns=['class', 'id'])  # Split feature and label
X = pd.DataFrame(data)

X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.3, random_state=42)

output = 'add'
n_clusters = len(np.unique(y_train))
print(n_clusters)
clf = KMeans(n_clusters=n_clusters, random_state=42)
clf.fit(X_train)
y_labels_train = clf.labels_
y_labels_test = clf.predict(X_test)
print(y_train)
if output == 'add':
    X_train['km_clust'] = y_labels_train
    X_test['km_clust'] = y_labels_test
elif output == 'replace':
    X_train = y_labels_train[:, np.newaxis]
    X_test = y_labels_test[:, np.newaxis]
else:
    raise ValueError('output should be either add or replace')

model = LogisticRegression(random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
print('Accuracy: {}'.format(accuracy_score(y_test, y_pred)))
print(len(X.columns))
pickle.dump(clf, open('goodluckScotty', 'wb'))
