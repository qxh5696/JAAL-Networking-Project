"""
File: summarize.py
Description: Module containing the implementation to the summarization module.
Language: python3
Authors: Qadir Haqq, Theodora Bendlin, John Tran
"""

import numpy as np
import util
import pandas as pd
from sklearn.cluster import KMeans
from scapy.utils import PcapReader
from scapy.layers.inet import IP


def summarize_packet_data(df, r=12, k=200, p=25):
    """
    Main summarization function for a batch of packets. Performs the following steps:

    (1) Filtering and normalization
    (2) Dimensionality reduction using SVD
    (3) Final representation construction using clustering

    @parameter df (Dataframe) packet dataframe containing a batch of size "n"
    @parameter r (int) the number of components to retain after SVD
    @parameter k (int) the number of clusters
    @parameter p (int) the number of columns in the packet summary

    @returns (int) the summary mode that was used
    @returns (object) the final summary representation
    """

    # Normalization step to bound values between 0 and 1
    normalized_df = normalize_packet_dataframe(df)
    
    # Perform SVD composition with keeping the top (r) values
    # Using top 20% for implementation phase
    Xp, Ur, Sigr, Vr = perform_svd_decomp(normalized_df, r)

    # Two methods for generating final summaries using clustering
    # Method to be used is based on formula from Section 4.3
    if (r * (k + p + 1)) + k < k * (p + 1):
        return 2, create_split_summary(Ur, Sigr, Vr, k)
    else:
        return 1, create_combined_summary(Xp, k)


def normalize_packet_dataframe(df):
    """
    Normalizes the packet header values for a n x p matrix
    X.

    @parameter df (DataFrame) the original dataframe of integer values
    @returns normalized_df (Dataframe) normalized dataframe
    """

    # Create copy to retain integrity of original values
    normalized_df = df.copy()
    for c in normalized_df.columns:
        max_val = normalized_df[c].max()
        normalized_df[c] = normalized_df[c].apply(lambda x: (x / max_val) if max_val != 0 else 0)

    return normalized_df


def perform_svd_decomp(df, r):
    """
    Performs SVD according to the definitions provided in the paper.
    Returns two reduced representations that could be used in the
    final step: Xp and u_r, sig_r, v_r.

    See Section 4.2 of the Jaal paper for more details.

    @parameter df (Dataframe) the dataframe to reduce
    @parameter r (int) the number of top n components to keep after SVD

    @returns Xp, (u_r, sig_r, v_r) (numpy arr) the matrix representations of summary data

    :param df:
    :param r:
    :return:
    """

    df = df.dropna(axis=0)

    np_array = df.to_numpy(dtype='float32', copy=True)

    u, sig, v = np.linalg.svd(np_array, full_matrices=False)
    vt = np.transpose(v)

    # Rank can be further reduced by setting r largest values to themselves,
    # and the rest to zero
    sig_p = sig
    for idx in range(r, len(sig)):
        sig_p[idx] = 0

    Xp = np.dot(np.dot(u, np.diag(sig_p)), vt)

    # Since sig_p only keeps the r largest values, we can remove the corresponding
    # columns from u and v
    u_r = np.delete(arr=u, obj=np.s_[r:], axis=1)
    sig_r = np.delete(arr=sig_p, obj=np.s_[r:], axis=0)
    v_r = np.transpose(np.delete(arr=vt, obj=np.s_[r:], axis=0))

    return Xp, u_r, sig_r, v_r


def create_combined_summary(Xp, k):
    """
    Creates the first approach to a summary representation.
    Performs kmeans++ clustering, then concatenates a membership
    count vector for each cluster according to Section 4.3.

    @parameter Xp (numpy array) the reduced summary array
    @parameter k (int) the number of clusters

    @returns S1m (numpy array), the final packet summary
    :param Xp:
    :param k:
    :return:
    """

    clustering_results, c = get_clustering_results(Xp, k)

    # Representation is cluster centers | c
    return np.hstack((clustering_results, c))


def create_split_summary(Ur, Sigr, Vr, k):
    """
    Creates the second approach to a summary representation.
    Performs kmeans++ clustering, then concatenates a membership
    count vector for each cluster and the dot product of the reduced
    rank SVD results, according to Section 4.3.

    @parameter Ur, Sigr, Kr (numpy array) the reduced summary array components
    @parameter k (int) the number of clusters

    @returns S2m (numpy array), the final packet summary
    :param Ur:
    :param Sigr:
    :param Vr:
    :param k:
    :return:
    """

    clustering_results, c = get_clustering_results(Ur, k)

    # Computing the product of Sigr and VrT, referred to as e
    e = np.dot(np.diag(Sigr), np.transpose(Vr))

    return {"clusters": clustering_results, "e": e, "c": c}


def get_clustering_results(X, k):
    """
    Helper function that will perform the k-means++ algorithm and
    compute the membership count vector (c).

    @parameter X (numpy array) the 2D array to be clustered
    @parameter k (int) the number of clusters

    @returns clustering_results (numpy array) the centroids from each cluster
    @returns c (numpy array), the array of membership counts for each cluster
    :param X:
    :param k:
    :return:
    """

    # Getting the initial centroids and other data
    kmeans_results = KMeans(n_clusters=k, init='k-means++').fit(X)
    clustering_results = kmeans_results.cluster_centers_

    # Membership count vector (c)
    c = np.zeros((k, 1))
    for cluster in range(0, k):
        c[cluster] = sum(1 for x in kmeans_results.labels_ if x == cluster)

    return clustering_results, c

def _test_summarization():
    df = pd.DataFrame(columns=util.TCP_COLS)
    i = 0
    for pkt in PcapReader('201601011400.pcap'):
        print(pkt[IP].dst)
        if i == 100:
            break
        _, df = util.add_pcap_packet_to_df(pkt, df)
        i += 1
    print(summarize_packet_data(df))

if __name__ == '__main__':
    _test_summarization()