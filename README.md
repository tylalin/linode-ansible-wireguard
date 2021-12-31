# linode-ansible-wireguard
Automating Linode VPS deployment and WireGuard implementation. 

# Ansible WireGuard workflow on Linode

Spinning up a VPS on Linode with your favourite Linux distro and setting up a WireGuard server is truly easy and intuitive on its WebUI portal. I have done the same process of a VPS setup and its required configuration so many times on all those different cloud providers like Digital Ocean and Vultr. They are almost the same in user experience on each portal. However, I can't use it all platforms at the same time to make my workflow template-able like any other things in life. Repeating the same damn things is a bit boring and tedious. I am not a big fan of repeating the same thing again and again as I am lazy enough to get bored easily. Thus always looking for the easier way to make my life less miserable. Plus the cloud is not supposed to consume like that. It has its own way; DevOps way of life. So I have invested a week worth of research and implementing Ansible playbooks to automate my workflow on Linode.&#x20;

In this article, I would like to share the Ansible workflow I use on Linode. Here is the list of prerequisites before straight delve into the tutorial.

* A valid Linode Personal Access Token (API Token)
* Python version 2.7 or higher installed&#x20;

```
  python --version
```

* The official Python library for the Linode API v4

```
  sudo apt-get install python-pip
  sudo pip install linode_api4
```

* Ansible's 2.8 release
* Git
* Basic understanding of Ansible ad-hoc and playbooks concept

### Setting up Ansible Playbooks

* Git clone [https://github.com/tylalin/linode-ansible-wireguard.git](https://github.com/tylalin/linode-ansible-wireguard.git)
* Change the password inside ".vault-pass" file to desired one.
* To encrypt the plain-text root password with ansible-vault, run the following command.

```
 ansible-vault encrypt_string 'PlainTextPassword' --name 'password'
```

Sample output as below

```
password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          30312345678639613832373335313062366536313334316465303462656664333064373933393831
          3432313261613532346134622761316363363535326333360a626431376265373133653535373238
          38323166666665376366663964343830633445563537623065356364343831316439396462343935
          6233646239363434380a383433643763373066633535366137346638123456789064353466303734
          1245
Encryption successful
```

* Copy the encrypted password block into var/linode\_wg.yml
* Repeat the same encryption process with Linode API token
* As you are in var/linode\__wg.yml, update the following variables as desired._

{% code title="vars/linode_wg.yml" %}
```
ssh_keys: >
        ['<< Your SSH Public Key Here! >>', '~/.ssh/id_rsa.pub']

hostname: tyla-linode-wg01 # change the hostname as required

type: g6-nanode-1 # change Linode Plan as required. Here it uses the Linode's Shared CPU Nanode (RAM: 1 GB, CPUs: 1 & Storage: 25 GB) as my node

region: ap-south # change the region as required. Here it uses Singapore as my region

image: linode/ubuntu20.04 # change the image as required. Here it uses the Linode's Ubuntu20.04 as my base image

gt: tyla-linode-wg # it uses for group and tag names

wg_ip: '192.168.69.254' # wireguard server wg0 virtual interface IP

my_ip: '1.2.3.4' # your public IP for SSH remote access restriction

password: << Your "ansible-vault encrypt_string 'YourSecretHere' --name 'password'" Output Here! >>  # root password used for the new Linode which is encrypted with ansible-vault for security
          
token: << Your "ansible-vault encrypt_string 'YourLinodeAPITokenHere' --name 'token'" Output Here! >> # Linode API Token created on your Linode portal which is encrypted with ansible-vault for security

```
{% endcode %}

* Also note that wg\_ip: variable's IP subnet needs to be same as the subnet used in wg/users.csv as shown in below sample.

{% code title="wg/users.csv" %}
```
usr,ip
1,192.168.69.1
2,192.168.69.2
3,192.168.69.3
4,192.168.69.4
5,192.168.69.5
```
{% endcode %}

* Make sure that ansible.cfg is configured correctly to work with Ansible playbooks.

{% code title="ansible.cfg" %}
```
[defaults]
host_key_checking = False
vault_password_file = ./.vault-pass # ansible-vault password file
[inventory]
enable_plugins = linode
```
{% endcode %}

* Prepare the Jinja2 templates as following.

{% code title="templates/wg0.conf.j2" %}
```
[Interface]
Address = {{ wg_ip }}/32
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {{ ansible_default_ipv4.interface }} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {{ ansible_default_ipv4.interface }} -j MASQUERADE
ListenPort = 51820
PrivateKey = {{ wg_pri.stdout }}

```
{% endcode %}

{% code title="templates/wg_peer.j2" %}
```
[Interface]
PrivateKey = {{ prikey }}
Address = {{ item.ip }}
DNS = 1.1.1.1, 1.0.0.1 

[Peer]
PublicKey = {{ wg_pub.stdout }}
AllowedIPs = 0.0.0.0/0
Endpoint = {{ hostvars[inventory_hostname]["inventory_hostname"] }}:51820
PersistentKeepalive = 25

```
{% endcode %}

{% code title="templates/wg_srv.j2" %}
```
[Peer]
# user{{ item.usr }} wg
PublicKey = {{ pubkey }}
AllowedIPs = {{ item.ip }}/32

```
{% endcode %}

### Prepare and Execute Ansible Playbooks

* Believe it or not. It is all good and ready to run wg\_build.yml playbook now.

```
# To run the whole wg_build.yml playbook
$ ansible-playbook playbooks/wg_build.yml

# To run a specific play in wg_build.yml playbook
$ ansible-playbook playbooks/wg_build.yml --tags infra
$ ansible-playbook playbooks/wg_build.yml --tags init
$ ansible-playbook playbooks/wg_build.yml --tags wg

# To run unit testing on Linode initial config and wireguard config
$ ansible-playbook playbooks/wg_build.yml --tags conf-test
$ ansible-playbook playbooks/wg_build.yml --tags wg-test
or
$ ansible-playbook playbooks/wg_build.yml --tags tests
```

* Relevant notes are added to each playbook for further description as well.

{% code title="playbooks/wg_build.yml" %}
```
---
# First play is used to create a new linode with your Linode portal API Token as below play
- name: CREATE A NEW LINODE
  hosts: localhost
  tags: [ always, infra ] # those tags can be used for easy access to a particular play of the whole playbook
  vars_files:
    - ../vars/linode_wg.yml

  tasks:
    - name: Create a new Linode.
      linode_v4:
        label: "{{ hostname }}"
        access_token: "{{ token }}"
        type: "{{ type }}"
        region: "{{ region }}"
        image: "{{ image }}"
        root_pass: "{{ password }}"
        authorized_keys: "{{ ssh_keys }}"
        group: "{{ gt }}"
        tags: "{{ gt }}"
        state: present
      register: tyla

    - name: Display info about my Linode instance # this task is used for the new Linode verificaiton
      debug:
        msg: "{{ hostname }} | {{ tyla.instance.id }} | {{ tyla.instance.ipv4[0] }}"

    - name: Add new host to in-memory inventory # this task is used to add the Linode public IP to Ansible in-memory inventory along with its group name
      add_host:
        name: "{{ tyla.instance.ipv4[0] }}"
        groups: linode_wg
      changed_when: false

    - name: Wait for Linode to listen on port 22 # ensure that the new Linode is running and ready to move on with the next play
      wait_for:
        state: started
        host: "{{ tyla.instance.ipv4[0] }}"
        port: 22

# Second play is used for a standard initial configuration required on Ubuntu 20.04 Linux box
- name: INITIAL CONFIGURATION ON THE NEW LINODE
  tags: init
  hosts: linode_wg
  user: root
  vars_files:
    - ../vars/linode_wg.yml

  tasks:
    - name: Initial Linode Configuration
      tags: conf
      block: # block is used here for controlling which set of tasks in each I want to execute. e.g., here I tag 'conf'
        - name: Set hostname
          hostname: name="{{ hostname }}"

        - name: Update apt repo and cache
          apt: update_cache=yes force_apt_get=yes cache_valid_time=3600

        - name: Upgrade all apt packages
          apt: upgrade=dist force_apt_get=yes

        - name: Check if a reboot is needed after apt upgrade
          register: reboot
          stat: path=/var/run/reboot-required get_md5=no

        - name: Reboot the Ubuntu Linode
          reboot:
            msg: "Reboot initiated by Ansible due to kernel updates"
            connect_timeout: 5
            reboot_timeout: 300
            pre_reboot_delay: 0
            post_reboot_delay: 30
            test_command: uptime
          when: reboot.stat.exists

        - name: Enable packet forwarding for IPv4 # this task is important for WireGuard to work correctly by allowing IP forwarding thru the node
          sysctl:
            name: net.ipv4.ip_forward
            value: '1'
            sysctl_set: true
            state: present
            reload: true

        - name: Configure SSH key authentication only # desired state of /etc/ssh/sshd_config is used to restrict ssh remote access
          copy: src=../files/sshd_config dest=/etc/ssh/sshd_config
          notify: Restart SSH

        - name: Allow SSH in UFW
          ufw:
            rule: limit
            port: ssh
            proto: tcp
            src: {{ my_ip }}
            dest: 0.0.0.0/0

        - name: Allow WireGuard in UFW
          ufw:
            rule: allow
            port: '51820'
            proto: udp
            dest: 0.0.0.0/0

        - name: Deny everything and enable UFW
          ufw:
            state: enabled
            policy: deny
            log: true

    - name: Unit testing on initial configuration # unit testing to verify the system configured and tags are used to run specific block
      tags: [ never, tests, conf_test ]
      block: 
        - name: Get the output of /etc/sysctl.conf file
          command: tail -1 /etc/sysctl.conf
          register: sysctl
          changed_when: false

        - name: Test if /etc/sysctl.conf is configured correctly
          assert:
            that:
              - "'net.ipv4.ip_forward=1' in sysctl.stdout_lines"
            success_msg: "[PASS] IP Forwarding is configured correctly."
            fail_msg: "[FAIL] IP Forwarding is not configured or misconfigred."

        - name: Get the output of /etc/ssh/sshd_config
          command: cat /etc/ssh/sshd_config
          register: ssh
          changed_when: false

        - name: Test if /etc/ssh/sshd_config is configured correctly
          assert:
            that:
              - "'PermitRootLogin prohibit-password' in ssh.stdout_lines"
              - "'PubkeyAuthentication yes' in ssh.stdout_lines"
              - "'PasswordAuthentication no' in ssh.stdout_lines"
              - "'PermitEmptyPasswords no' in ssh.stdout_lines"
            success_msg: "[PASS] SSH Daemon is configured correctly."
            fail_msg: "[FAIL] IP Forwarding is not configured or misconfigred."

  handlers:
    - name: Restart SSH
      systemd:
        state: restarted
        name: ssh

# Third play is for WireGuard installation and configuration for both server and peers
- name: WIREGUARD INSTALLATION AND CONFIGURATION
  tags: wg
  hosts: linode_wg
  user: root
  vars_files:
    - ../vars/linode_wg.yml

  tasks:
    - name: Installing and Configurating WireGuard
      block:
        - name: Install WireGuard and QRencode on the Linode
          apt:
            name: [ wireguard, qrencode ]
            state: present
  
        - name: Generate WireGuard keypair
          shell: wg genkey | tee /etc/wireguard/pri | wg pubkey > /etc/wireguard/pub
          args:
            creates: /etc/wireguard/pri
  
        - name: Register private key
          shell: cat /etc/wireguard/pri
          register: wg_pri
          changed_when: false
  
        - name: Register public key
          shell: cat /etc/wireguard/pub
          register: wg_pub
          changed_when: false
  
        - name: Setup wg0 virtual interface
          template:
            src: ../templates/wg0.conf.j2 # Jinja2 template is used for templating the wg0.conf files
            dest: /etc/wireguard/wg0.conf
            owner: root
            group: root
            mode: 0640
  
        - name: Start and enable WireGuard service
          systemd:
            state: started
            enabled: true
            name: wg-quick@wg0.service

    - name: Unit testing on WireGuard configuration # unit testing for wireguard configuraiton
      tags: [ never, tests, wg_test ]
      block: 
        - name: Check the private key file location
          stat:
            path: /etc/wireguard/pri
          register: pri_key_file

        - name: Test if the private key file exists
          debug:
            msg: "[PASS] The private key file exists."
          when: pri_key_file.stat.exists

        - name: Register private key
          shell: cat /etc/wireguard/pri
          register: wg_pri
          changed_when: false

        - name: Dispaly WireGuard Private Key
          debug: var=wg_pri.stdout

        - name: Check the public key file location
          stat:
            path: /etc/wireguard/pub
          register: pub_key_file

        - name: Test if the public key file exists
          debug:
            msg: "[PASS] The public key file exists."
          when: pub_key_file.stat.exists
        
        - name: Register public key
          tags: always
          shell: cat /etc/wireguard/pub
          register: wg_pub
          changed_when: false
        
        - name: Dispaly WireGuard Public Key
          debug: var=wg_pub.stdout

    - name: WireGuard peer(s) configuration # this block is only executed on localhost but not on the newly created Linode so 'delegate_to:' must be used.
      delegate_to: localhost 
      block:
        - name: Read users.csv file 
          read_csv:
            path: ../wg/users.csv
          register: users

        - name: Generate WireGuard user(s) keypair and configuration # loop thru users.csv file and produce both server and peers configs
          include_tasks: wg_user.yml
          loop: "{{ users.list }}"

    - name: Update WireGuard server's wg0.conf with wg0_peer.conf # this block is executed on the Linode's wireguard server
      block:
        - name: Merge wg0_peer.conf into WireGuard server's wg0.conf
          lineinfile:
            line: "{{ lookup('file', '../wg/wg0_peer/wg0_peer_{{ ansible_date_time.epoch }}.conf') }}"
            dest: /etc/wireguard/wg0.conf
          notify: Restart WireGuard
  
  handlers:
    - name: Restart WireGuard # everytime updating wg0.conf it needs to restart the wireguard service
      systemd:
            state: restarted
            name: wg-quick@wg0.service

```
{% endcode %}

{% code title="playbooks/wg_user.yml" %}
```
---
- name: Create directory for user{{ item.usr }} # ensure that 'user' and its relevant subdirectories are created.
  file:
    path: ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/
    state: directory

- name: Generate WireGuard peer's keypair for user{{ item.usr }} # issue wireguard peer's keypair
  shell: wg genkey | tee ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}.pri.key | wg pubkey | tee ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}.pub.key
  args:
    creates: ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}.pri.key # do not run this task if the private key is already created for idempotency

- name: Generate WireGuard peer's configuration for user{{ item.usr }} # produce wireguard peers' configs with its private key and server public key
  vars: 
    prikey: "{{ lookup('file', '../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}.pri.key') }}"
  template:
    src: ../templates/wg_peer.j2
    dest: ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}_peer.conf

- name: Generate QRcode for WireGuard peer's configuration for user{{ item.usr }} # encode the peers' configs to QRCode in .png format for mobile devices
  shell: qrencode -o ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}_peer.png -t png < ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}_peer.conf

- name: Ensures ../wg/_QRCode/ dir exists
  file: 
    path: ../wg/_QRCode/  
    state: directory

- name: Copy user{{ item.usr }} QRcode to _QRCode folder # QRCode collection for easy distribution to the end VPN users
  copy:
    src: ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}_peer.png
    dest: ../wg/_QRCode/user{{ item.usr }}.png

- name: Generate WireGuard server's configuration for user{{ item.usr }} # produce the server side wireguard configs for easy rebuild and idempotency
  vars: 
    pubkey: "{{ lookup('file', '../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}.pub.key') }}"
  template:
    src: ../templates/wg_srv.j2
    dest: ../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}_srv.conf

- name: Merge user{{ item.usr }}_srv.conf into wg0_peer.conf # merge all server side configs into one conf file to directly deliver it to wireguard server and apply
  lineinfile:
    line: "{{ lookup('file', '../wg/user/usr_{{ item.usr }}_{{ item.ip }}/{{ item.usr }}_srv.conf') }}"
    dest: ../wg/wg0_peer/wg0_peer_{{ ansible_date_time.epoch }}.conf
    create: true

```
{% endcode %}

* To tear down the Linode, run playbooks/wg\_PURGE.yml as below.

```
$ ansible-playbook playbooks/wg_PURGE.yml
```

{% code title="playbooks/wg_PURGE.yml" %}
```
---
# This play is for destroying the running wireguard server on Linode. RUN IT CAREFULLY!
- name: Delete Linode
  hosts: localhost
  vars_files:
    - ../vars/linode_wg.yml

  tasks:
    - name: Delete your Linode Instance.
      linode_v4:
        label: "{{ hostname }}"
        access_token: "{{ token }}"
        state: absent

```
{% endcode %}

Now you see how easy it is to build and tear down WireGuard VPN server Linode with one Ansible command in DevOpsy fashion. Hope it's helpful and informative.