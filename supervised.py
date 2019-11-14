import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier

bad_features = ['id', 'class', 'Mean_backward_inter_arrival_time_difference', 'Mean_backward_TTL_value',
                'Max_backward_inter_arrival_time_difference', 'STD_backward_inter_arrival_time_difference']


def train(training_set):
    df = pd.read_csv(training_set)
    labels = df['class']
    # Remove
    features = df.drop(bad_features, axis=1)

    clf = RandomForestClassifier()
    clf.fit(features, labels)
    return clf


def tester(model, test_set):
    clf = model
    test = pd.read_csv(test_set)
    y = test['class']
    test = test.drop(bad_features, axis=1)
    print('Model Score: ' + str(clf.score(test, y)))

'''
#pickle.dump(tester('full.csv', 'bad_test.csv'), open('model.pkl', 'wb'))
file = open('model.pkl', 'rb')

test = pickle.load(file)
file.close()
tester(test, 'bad_test.csv')

'''