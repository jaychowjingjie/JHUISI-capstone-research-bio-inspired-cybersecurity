import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier

bad_features = ['id', 'class']


def train(training_set, model_filename):
    df = pd.read_csv(training_set)
    labels = df['class']
    features = df.drop(bad_features, axis=1)

    clf = RandomForestClassifier(n_estimators=100, random_state=6)
    clf.fit(features, labels)
    pickle.dump(clf, open(model_filename, 'wb'))


def tester(model, test_set):
    clf = model
    test = pd.read_csv(test_set)
    y = test['class']
    test = test.drop(bad_features, axis=1)
    print('Model Score: ' + str(clf.score(test, y)))


# train('full2.csv', 'supervised_model2.pkl')
'''
df1 = pd.read_csv('normal2.csv')
df2 = pd.read_csv('hancitor.csv')
df3 = pd.read_csv('ursnif.csv')
df4 = pd.read_csv('trickbot.csv')
dfs = [df1, df2, df3, df4]
full = pd.concat(dfs, ignore_index=True)
full.fillna(0, inplace=True)
full.drop(['id'], axis=1, inplace=True)
full.to_csv('full2.csv')

file = open('model.pkl', 'rb')

test = pickle.load(file)
file.close()
tester(test, 'bad_test.csv')

'''