import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

from scapy.all import rdpcap


def classify(train_features, train_labels, test_features, test_labels):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions


def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    accuracies = []
    precisions = []

    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test)

        prediction_results = predictions == y_test

        accuracy  = np.sum(prediction_results)/len(predictions)

        precision = np.mean([np.sum(np.logical_and(predictions == i, prediction_results))/np.sum(predictions == i)
            for i in range(1,101) if np.sum(predictions == i) > 0]) # pondérée ? to do

        accuracies.append(accuracy)
        precisions.append(precision)

    print("Mean of accuracies over " + str(folds) + " folds:", np.mean(accuracies))
    print("Variance of accuracies over " + str(folds) + " folds:", np.var(accuracies))

    print("Mean of precisions over " + str(folds) + " folds:", np.mean(precisions))
    print("Variance of precisions over " + str(folds) + " folds:", np.var(precisions))


def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    features = []
    labels = []

    for cell in range(1,101):
        for i in range(1,101): # can be modified
            trace = rdpcap("./traces/cell" + str(cell) + "/iteration" + str(i))

            sum_pack_len = sum([packet['IP'].len for packet in trace])
            sum_payl_len = sum([len(packet.payload) for packet in trace])
            num_packets  = len(trace)

            features.append((sum_pack_len, sum_payl_len, num_packets))
            labels.append(cell)

    return features, labels
        

def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    print("data loaded")
    perform_crossval(features, labels, folds=10)
    

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)