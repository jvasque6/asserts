FROM registry.gitlab.com/fluidsignal/asserts/mocks/smb:weak

ENV FLAVOR hard

EXPOSE 139/tcp 445/tcp

COPY etc_samba_smb.conf-hard /etc/samba/smb.conf

ENTRYPOINT ["/usr/sbin/smbd", "-F"]

