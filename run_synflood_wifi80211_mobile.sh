python3 utils/syn_entropy.py \
  --pcap "results/wifi80211_mobile/test_pcap/wifi80211_mobile_core_left-*.pcap" \
  --outdir results/wifi80211_mobile/entropy \
  --interval 0.5 \
  --window-bins 10 \
  --dst-prefix 10.3. \
  --attack-start 2 \
  --attack-stop 39