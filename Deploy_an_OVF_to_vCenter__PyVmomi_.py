	try:
        si = connect.SmartConnect(host=args.host,
                                  user=args.user,
                                  pwd=args.password,
                                  port=args.port)
    except:
        print "Unable to connect to %s" % args.host
        exit(1)
    objs = get_objects(si, args)
    manager = si.content.ovfManager
    spec_params = vim.OvfManager.CreateImportSpecParams()
    import_spec = manager.CreateImportSpec(ovfd,
                                           objs["resource pool"],
                                           objs["datastore"],
                                           spec_params)
    lease = objs["resource pool"].ImportVApp(import_spec.importSpec,
                                             objs["datacenter"].vmFolder)
    while(True):
        if (lease.state == vim.HttpNfcLease.State.ready):
            # Assuming single VMDK.
            url = lease.info.deviceUrl[0].url.replace('*', args.host)
            # Spawn a daemon thread to keep the lease active while POSTing
            # VMDK.
            keepalive_thread = Thread(target=keep_lease_alive, args=(lease,))
            keepalive_thread.start()
            # POST the VMDK to the host via curl. Requests library would work
            # too.
            curl_cmd = (
                "curl -Ss -X POST --insecure -T %s -H 'Content-Type: \
                application/x-vnd.vmware-streamVmdk' %s" %
                (args.vmdk_path, url))
            system(curl_cmd)
            lease.HttpNfcLeaseComplete()
            keepalive_thread.join()
            return 0
        elif (lease.state == vim.HttpNfcLease.State.error):
            print "Lease error: " + lease.state.error
            exit(1)
    connect.Disconnect(si)