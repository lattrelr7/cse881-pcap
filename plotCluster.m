function [] = plotCluster(X, clusterID, titlestr)
%
% function [] = plotCluster(X, clusterID, titlestr)
%
% Function to plot the result of clustering algorithm
%    Input: 
%       X : an N x d data matrix to be clustered (N: #data points, d:#features)
%       clusterID: an N x 1 vector (containing the cluster assignments from 1 .. k)
%       titlestr: title of the figure (e.g., kmeans, dbscan, etc)
%
% This function is limited to 2-dimensional input data with a maximum of 13
% unique clusters.
%
%  Example:
%       load fisheriris;
%       X = meas(:,1:2);
%       numClusters = 3;
%       I = kmeans(X, numClusters);
%       plotCluster(X, I);

figure;
set(gcf,'color','white');
labels = unique(clusterID);

%Do PCA for high dimensionality reduction
[coeff, scores] = princomp(X);

if (length(labels) > 13)
    warning('Error: number of clusters must be less than 13');
    return;
end;

markertype = {'r+';'ko';'bv';'g*';'ms';'yd';'cx';'r^';'k<';'b>';'gp';'mh';'y.'};

I = find(clusterID==labels(1));
scatter3(scores(I,1),scores(I,2),scores(I,3),markertype{1});
if ~isempty(titlestr)
    title(titlestr);
end;
hold;

for i=2:length(labels)
    I = find(clusterID==labels(i));
    scatter3(scores(I,1),scores(I,2),scores(I,3),markertype{i});
end;
hold off

figure;
silhouette(X,clusterID);