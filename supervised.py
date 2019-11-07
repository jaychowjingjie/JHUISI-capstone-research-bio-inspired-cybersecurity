import pandas as pd
from sklearn.ensemble import RandomForestClassifier


def tester(filename):
    df = pd.read_csv(filename)
    labels = df['class']
    features = df.drop(['id', 'class', 'Mean_backward_inter_arrival_time_difference', 'Mean_backward_TTL_value',
                        'Max_backward_inter_arrival_time_difference','STD_backward_inter_arrival_time_difference']
                       , axis=1)

    clf = RandomForestClassifier()
    clf.fit(features, labels)
    feature_importances = pd.DataFrame(clf.feature_importances_,
                                       index=features.columns,
                                       columns=['importance']).sort_values('importance', ascending=False)
    test = pd.read_csv('test2.csv')
    y = test['Label']
    test = test.drop(['id', 'Label', 'Mean_backward_inter_arrival_time_difference', 'Mean_backward_TTL_value',
                      'Max_backward_inter_arrival_time_difference', 'STD_backward_inter_arrival_time_difference'],
                     axis=1)
    print(clf.score(test, y))
    return feature_importances


print(tester('full.csv'))

