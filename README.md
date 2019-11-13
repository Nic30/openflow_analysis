# openflow_analysis
utils for analysis and optimization of config files/rule-sets from the cloud/OF environment

## Note that this is WIP as I currently collecting all the scripts which I am using in order to make this library

# Pipeline descriptions in controllers

* [faucet](https://github.com/faucetsdn/faucet/blob/master/faucet/faucet_pipeline.py)


# Related software/doc (to OF and OvS/OVN)
* [openflow specs](https://www.opennetworking.org/software-defined-standards/specifications/)
* [openflow reference](https://github.com/noxrepo/openflow)
* [faucet](https://github.com/faucetsdn/faucet) - OF controller 
* [kubernetes](https://github.com/kubernetes/kubernetes) - Container scheduler and manager
	* Kubernetes networking plugins
	* [kube-ovn](https://github.com/alauda/kube-ovn) - fixed cidr range per node
	* [ovn-kubernetes](https://github.com/ovn-org/ovn-kubernetes) - subnet per namespace
* [ryu](https://osrg.github.io/ryu/) - OF framework
* [POX](https://github.com/noxrepo/pox) - sucessor of original OF controller (NOX)
* [djoreilly/ovs-cheat.md](https://gist.github.com/djoreilly/c5ea44663c133b246dd9d42b921f7646)
* [microstack](https://opendev.org/x/microstack)
* [devstack](https://docs.openstack.org/devstack/latest/)
* [NFV Proofs of Concept](https://www.etsi.org/technologies/nfv/nfv-poc)

# Kubernetes comunication types

* https://kubernetes.io/docs/concepts/cluster-administration/networking/
* inside a Pod, Pod-Pod, Pod-Service, External-Service
 
 * pods on a same phys network as Node -> no NAT