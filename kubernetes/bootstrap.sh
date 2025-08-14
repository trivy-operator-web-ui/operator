#!/bin/bash

helm install \
    ingress-nginx \
    ingress-nginx \
    --repo https://kubernetes.github.io/ingress-nginx \
    --namespace ingress-nginx \
    --create-namespace

helm install \
    trivy-operator \
    trivy-operator \
    --repo https://aquasecurity.github.io/helm-charts/ \
    -f ../helm/values.trivy.yaml \
    --namespace trivy-system \
    --create-namespace

kubectl apply -k .