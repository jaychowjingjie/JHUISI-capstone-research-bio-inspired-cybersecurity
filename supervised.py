import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier


def tester(train, test_set):
    df = pd.read_csv(train)
    labels = df['class']
    features = df.drop(['id', 'class', 'Mean_backward_inter_arrival_time_difference', 'Mean_backward_TTL_value',
                        'Max_backward_inter_arrival_time_difference','STD_backward_inter_arrival_time_difference']
                       , axis=1)

    clf = RandomForestClassifier()
    clf.fit(features, labels)
    feature_importance = pd.DataFrame(clf.feature_importances_,
                                       index=features.columns,
                                       columns=['importance']).sort_values('importance', ascending=False)
    print(feature_importance)
    test = pd.read_csv(test_set)
    y = test['Label']
    test = test.drop(['id', 'Label', 'Mean_backward_inter_arrival_time_difference', 'Mean_backward_TTL_value',
                      'Max_backward_inter_arrival_time_difference', 'STD_backward_inter_arrival_time_difference'],
                     axis=1)
    print('Model Score: ' + str(clf.score(test, y)))
    return clf


pickle.dump(tester('full.csv', 'bad_test.csv'), open('model.pkl', 'wb'))

