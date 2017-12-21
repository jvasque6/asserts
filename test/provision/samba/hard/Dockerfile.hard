FROM registry.gitlab.com/fluidsignal/asserts/mocks/smb:weak 

COPY etc_samba_smb.conf-hard /etc/samba/smb.conf

ENTRYPOINT ["/usr/sbin/smbd", "-F"]

